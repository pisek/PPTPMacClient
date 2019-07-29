import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.util.List;
import java.util.Scanner;

public class Main {

    private static final String CONFIG_PATH = "/etc/ppp/peers/pptp";
    private static final String LOG_PATH = "/tmp/ppp.log";
    private static final String LABEL_CONNECTED = "Connected";
    private static final String LABEL_DISCONNECTED = "Disconnected";
    private static final String BUTTON_CONNECT = "Connect";
    private static final String BUTTON_DISCONNECT = "Disconnect";

    private static class ConfigBuilder {
        String remoteaddress = null;
        String user = null;
        String password = null;
        String ms_dns = "8.8.8.8";
        String logfile = LOG_PATH;
        String plugin = "PPTP.ppp";
        Integer redialcount = 1;
        Integer redialtimer = 5;
        Integer idle = 1800;
        Integer mru = null;
        Integer mtu = 1320;
        boolean receive_all = true;
        String novj = "0:0";
        boolean ipcp_accept_local = true;
        boolean ipcp_accept_remote = true;
        boolean noauth = false;
        boolean refuse_pap = false;
        boolean refuse_chap_md5 = false;
        boolean refuse_eap = true;
        boolean hide_password = true;
        boolean noaskpassword = false;
        boolean mppe_stateless = false;
        boolean mppe_128 = false;
        boolean require_mppe = true;
        boolean nomppe_40 = true;
        boolean nomppe_128 = true;
        boolean mppe_stateful = true;
        boolean passive = true;
        boolean looplocal = true;
        boolean nodetach = true;
        boolean defaultroute = true;
        boolean usepeerdns = true;
        boolean debug = true;

        String build() {
            StringBuilder sb = new StringBuilder();
            for (Field f : this.getClass().getDeclaredFields()) {
                try {
                    if (f.getAnnotatedType().getType().equals(boolean.class)) {
                        if (f.getBoolean(this)) {
                            sb.append(f.getName().replace('_', '-')).append('\n');
                        }
                    } else if (f.get(this) != null) {
                        sb.append(f.getName().replace('_', '-')).append(' ').append(f.get(this)).append('\n');
                    }
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
            }
            return sb.toString();
        }
    }

    public static void main(String[] args) throws Exception {
//        Runnable sc = new Main().statusChecker;
//        Class<? extends Runnable> aClass = sc.getClass();
//        Method checkStatus = aClass.getDeclaredMethod("checkStatus");
//        checkStatus.setAccessible(true);
//        checkStatus.invoke(sc);
        if (!new File(CONFIG_PATH).canWrite()) {
            elevate();
            System.exit(0);
        } else {
            new Main().start();
        }
    }

    private static void elevate() throws IOException, URISyntaxException {
        File executor = File.createTempFile("Executor", ".sh");
        PrintWriter writer = new PrintWriter(executor, "UTF-8");

        writer.println("#!/bin/bash");
        writer.println();
        writer.println("java $* > /tmp/output.txt 2>&1 &");
        writer.close();
        executor.setExecutable(true);

        File elevator = File.createTempFile("Elevator", ".sh");
        writer = new PrintWriter(elevator, "UTF-8");
        writer.println("#!/bin/bash");
        writer.println();
        writer.println(String.format("osascript -e \"do shell script \\\"%s $*\\\" with administrator privileges\"",
                executor.getPath()));
        writer.close();
        elevator.setExecutable(true);

        Runtime.getRuntime().exec(String.format("%s -cp %s %s",
                elevator.getPath(),
                Main.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath(),
                Main.class.getName()));
    }

    private JTextField serverName = new JTextField();
    private JTextField username = new JTextField();
    private JPasswordField password = new JPasswordField();
    private JButton button = new JButton("wait");

    private JLabel statusLabel = new JLabel();
    private boolean connected = false;
    Runnable statusChecker = new Runnable() {
        private boolean stop = false;
        @Override
        public void run() {
            while (!stop) {
                connected = checkStatus();
                statusLabel.setText(connected ? LABEL_CONNECTED : LABEL_DISCONNECTED);
                switchButton(!connected);
                enableFields(!connected);
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        private boolean checkStatus() {
            boolean isConnected = false;
            try {
                Process p = Runtime.getRuntime().exec("ps aux");
                p.waitFor();
                isConnected = new Scanner(p.getInputStream()).findAll("[p]ppd").count() != 0;
            } catch (IOException | InterruptedException e) {
                throw new RuntimeException(e);
            }
            return isConnected;
        }

        public void stop() {
            this.stop = true;
        }
    };

    private void start() {

        readConfig();
        enableFields(false);

        JFrame root = new JFrame("PPTP Mac Client");
        button.addActionListener(this::handleConnection);
        root.setLayout(new GridLayout(5, 2, 5, 5));
        root.add(new JLabel("Server: "));
        root.add(serverName);
        root.add(new JLabel("Username: "));
        root.add(username);
        root.add(new JLabel("Password: "));
        root.add(password);
        root.add(new JPanel());
        root.add(button);
        button.setEnabled(false);

        root.add(new JLabel("Status: "));
        root.add(statusLabel);

        root.setSize(200, 200);
        root.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        root.setVisible(true);

        new Thread(statusChecker).start();
    }

    private void readConfig() {
        File configFile = new File(CONFIG_PATH);
        try {
            List<String> lines = Files.readAllLines(configFile.toPath());
            for (String line : lines) {
                String[] s = line.trim().split(" ");
                if (s[0].equals("remoteaddress")) {
                    serverName.setText(s[1]);
                } else if (s[0].equals("user")) {
                    username.setText(s[1]);
                } else if (s[0].equals("password")) {
                    password.setText(s[1]);
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void handleConnection(ActionEvent e) {
        enableFields(false);
        String config = generateConfig();
        saveConfig(config);

        connect();

        switchButton(false);
    }

    private void handleDisconnection(ActionEvent e) {
        disconnect();

        enableFields(true);

        switchButton(true);
    }

    private void switchButton(boolean toConnect) {
        button.removeActionListener(button.getActionListeners()[0]);
        button.setEnabled(true);
        if (toConnect) {
            button.setText(BUTTON_CONNECT);
            button.addActionListener(this::handleConnection);
        } else {
            button.setText(BUTTON_DISCONNECT);
            button.addActionListener(this::handleDisconnection);
        }
    }

    private void connect() {
        try {
            Runtime.getRuntime().exec("exec pppd call pptp >/dev/null 2>&1 &");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void disconnect() {
        try {
            Runtime.getRuntime().exec("exec kill -HUP `cat /var/run/ppp0.pid` >/dev/null 2>&1 &");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void saveConfig(String config) {
        File configFile = new File(CONFIG_PATH);
        try {
            Files.write(configFile.toPath(), config.getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void enableFields(boolean setting) {
        serverName.setEnabled(setting);
        username.setEnabled(setting);
        password.setEnabled(setting);
    }

    private String generateConfig() {
        ConfigBuilder b = new ConfigBuilder();
        b.remoteaddress = serverName.getText();
        b.user = username.getText();
        b.password = password.getText();
        return b.build();
    }

}