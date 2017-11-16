package cz.vsb.pvbps.project.form;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class MainApp extends Application {

	public static final String VIRUS_TOTAL_FOLDER_ANALYZER = "VirusTotal Folder Analyzer";

	@Override
	public void start(Stage stage) throws Exception {

		Parent root = FXMLLoader.load(getClass().getResource("/fxml/Scene.fxml"));

		Scene scene = new Scene(root);
		stage.setTitle(VIRUS_TOTAL_FOLDER_ANALYZER);
		stage.setScene(scene);
		stage.setResizable(false);
		stage.show();
	}

	/**
	 * The main() method is ignored in correctly deployed JavaFX application. main()
	 * serves only as fallback in case the application can not be launched through
	 * deployment artifacts, e.g., in IDEs with limited FX support. NetBeans ignores
	 * main().
	 *
	 * @param args
	 *            the command line arguments
	 */
	public static void main(String[] args) {
		// FileService service = new FileService();
		// List<ScannerVirusResult> scanFile = service.scanFile("");

		launch(args);
	}

}
