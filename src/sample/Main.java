package sample;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.GridPane;
import javafx.stage.Stage;

import java.io.*;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.util.List;
import java.util.Scanner;

public class Main extends Application {

//    private static final String CONFIG_PATH = "/etc/ppp/peers/pptp";
    private static final String CONFIG_PATH = "C:\\Users\\xxbcz\\Documents\\test.txt";
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

        String build() {
            StringBuilder sb = new StringBuilder("debug\n");
            for (Field f : this.getClass().getDeclaredFields()) {
                try {
                    if (f.getAnnotatedType().getType().equals(boolean.class)) {
                        if (f.getBoolean(this)) {
                            sb.append("    ").append(f.getName().replace('_', '-')).append('\n');
                        }
                    } else if (f.get(this) != null) {
                        sb.append("    ").append(f.getName().replace('_', '-')).append(' ').append(f.get(this)).append('\n');
                    }
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
            }
            return sb.toString();
        }
    }

    public static void main(String[] args) throws Exception {
        if (false) {
            elevate();
        } else {
            launch(args);
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

        Runtime.getRuntime().exec(String.format("%s -cp %s Main",
                elevator.getPath(),
                Main.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath()));
    }

    private TextField serverName = new TextField();
    private TextField username = new TextField();
    private PasswordField password = new PasswordField();
    private Button button = new Button("Connect");

    private Label statusLabel = new Label("Disconnected");
    private boolean connected = false;
    private Runnable statusChecker = new Runnable() {
        @Override
        public void run() {
            while (true) {
                connected = checkStatus();
                statusLabel.setText(connected ? LABEL_CONNECTED : LABEL_DISCONNECTED);
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        private boolean checkStatus() {
            // TODO
            return false;
        }
    };

    @Override
    public void start(Stage primaryStage) throws Exception {

        readConfig();

        GridPane root = new GridPane();
        button.addEventHandler(MouseEvent.MOUSE_CLICKED, e -> handleConnection());
        root.addRow(0, new Label("Server: "), serverName);
        root.addRow(1, new Label("Username: "), username);
        root.addRow(2, new Label("Password: "), password);
        root.addRow(3, button);

        root.addRow(4, new Label("Status: "), statusLabel);
        primaryStage.setTitle("PPTP Mac Client");
        primaryStage.setScene(new Scene(root, 300, 275));
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

    private void handleConnection() {
        disableFields();
        String config = genrateConfig();
        saveConfig(config);

        connect();
    }

    private void connect() {
        // TODO
    }

    private void saveConfig(String config) {
        File configFile = new File(CONFIG_PATH);
        try {
            Files.write(configFile.toPath(), config.getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void disableFields() {
        serverName.setDisable(true);
        username.setDisable(true);
        password.setDisable(true);
    }

    private String genrateConfig() {
        ConfigBuilder b = new ConfigBuilder();
        b.remoteaddress = serverName.getText();
        b.user = username.getText();
        b.password = password.getText();
        return b.build();
    }

}