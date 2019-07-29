import javafx.application.Application;
import javafx.event.Event;
import javafx.scene.Scene;
import javafx.scene.canvas.Canvas;
import javafx.scene.canvas.GraphicsContext;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.GridPane;
import javafx.scene.paint.Color;
import javafx.stage.Stage;

import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.util.List;

public class Main extends Application {

    private static final String CONFIG_PATH = "/etc/ppp/peers/pptp";
//    private static final String CONFIG_PATH = "C:\\TEMP\\test.txt";
    private static final String LABEL_CONNECTED = "Connected";
    private static final String LABEL_DISCONNECTED = "Disconnected";

    private static class ConfigBuilder {
        String remoteaddress = null;
        String user = null;
        String password = null;
        String ms_dns = "8.8.8.8";
        String logfile = "/tmp/ppp.log";
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
        Runnable sc = new Main().statusChecker;
        Class<? extends Runnable> aClass = sc.getClass();
        Method checkStatus = aClass.getDeclaredMethod("checkStatus");
        checkStatus.setAccessible(true);
        checkStatus.invoke(sc);
//        if (!new File(CONFIG_PATH).canWrite()) {
//            elevate();
//            System.exit(0);
//        } else {
//            launch(args);
//        }
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

    private TextField serverName = new TextField();
    private TextField username = new TextField();
    private PasswordField password = new PasswordField();
    private Button button = new Button("Connect");

    private Label statusLabel = new Label("Disconnected");
    private Canvas led = new Canvas(20.0, 20.0) {{
        GraphicsContext gc = this.getGraphicsContext2D();
        gc.setFill(Color.RED);
        gc.fillOval(0,0, getWidth(), getHeight());
    }};
    private boolean connected = false;
    Runnable statusChecker = new Runnable() {
        @Override
        public void run() {
            while (true) {
                connected = checkStatus();
                statusLabel.setText(connected ? LABEL_CONNECTED : LABEL_DISCONNECTED);
                GraphicsContext gc = led.getGraphicsContext2D();
                gc.setFill(connected ? Color.GREEN : Color.RED);
                gc.fillOval(0,0, led.getWidth(), led.getHeight());

                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        private boolean checkStatus() {
            // do shell script "ps aux|grep '[p]ppd'|wc -l|awk {'print $1'}" with administrator privileges
            try {
                Process p = Runtime.getRuntime().exec("ps aux|grep '[p]ppd'|wc -l|awk {'print $1'}");
                BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                while (r.readLine() == null);
                String line = r.readLine();
                System.out.println(line);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return false;
        }
    };

    @Override
    public void start(Stage primaryStage) throws Exception {

        readConfig();

        GridPane root = new GridPane();
        button.addEventHandler(MouseEvent.MOUSE_CLICKED, this::handleConnection);
        root.addRow(0, new Label("Server: "), serverName);
        root.addRow(1, new Label("Username: "), username);
        root.addRow(2, new Label("Password: "), password);
        root.add(button, 1, 3);

        root.addRow(4, new Label("Status: "), new GridPane() {{addRow(0, led, statusLabel);}});
        primaryStage.setTitle("PPTP Mac Client");
        primaryStage.setScene(new Scene(root, 250, 150));
        primaryStage.show();
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

    private void handleConnection(Event e) {
        disableFields(true);
        String config = generateConfig();
        saveConfig(config);

        connect();

        button.addEventHandler(MouseEvent.MOUSE_CLICKED, this::handleDisconnection);
    }

    private void handleDisconnection(Event e) {
        disconnect();

        disableFields(false);

        button.addEventHandler(MouseEvent.MOUSE_CLICKED, this::handleConnection);
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

    private void disableFields(boolean setting) {
        serverName.setDisable(setting);
        username.setDisable(setting);
        password.setDisable(setting);
    }

    private String generateConfig() {
        ConfigBuilder b = new ConfigBuilder();
        b.remoteaddress = serverName.getText();
        b.user = username.getText();
        b.password = password.getText();
        return b.build();
    }

}