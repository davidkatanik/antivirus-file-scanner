package cz.vsb.pvbps.project.form.controller;

import java.io.File;
import java.net.URL;
import java.util.List;
import java.util.ResourceBundle;

import cz.vsb.pvbps.project.domain.ScannerVirusResult;
import cz.vsb.pvbps.project.form.MainApp;
import cz.vsb.pvbps.project.service.FileService;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.concurrent.WorkerStateEvent;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;

public class FXMLController implements Initializable {

	FileService fs = new FileService();

	@FXML
	private Button scanButton;

	@FXML
	private Button folderChooserDialogButton;

	@FXML
	private TextField folderTextFiled;

	@FXML
	private TableView<ScannerVirusResult> folderTable;

	private static Alert infoBox1;
	private static Alert infoBox2;

	@Override
	public void initialize(URL url, ResourceBundle rb) {

	}

	@FXML
	private void fileChooserDialogButton(ActionEvent event) {
		DirectoryChooser directoryChooser = new DirectoryChooser();
		directoryChooser.setTitle("Select folder for scan");
		File fileFromDialog = directoryChooser.showDialog(folderChooserDialogButton.getScene().getWindow());
		if (fileFromDialog != null) {
			String folderAbsolutePath = fileFromDialog.getAbsolutePath();

			folderTextFiled.setText(folderAbsolutePath);
			scanButton.setDisable(false);
		}
	}

	@FXML
	private void scanFolder(ActionEvent event) {
		String folderPath = folderTextFiled.getText();
		if (folderPath != null && !folderPath.isEmpty()) {

			Task<List<ScannerVirusResult>> task = new Task<List<ScannerVirusResult>>() {
				@Override
				protected List<ScannerVirusResult> call() throws Exception {
					return fs.scanFolder(folderPath);
				}
			};
			task.setOnScheduled(new EventHandler<WorkerStateEvent>() {

				@Override
				public void handle(WorkerStateEvent event) {
					showWaitingDialog(true);
				}
			});
			task.setOnSucceeded(new EventHandler<WorkerStateEvent>() {
				@Override
				public void handle(WorkerStateEvent handleEvent) {
					fillTableViewWithResult(task.getValue());
					showWaitingDialog(false);
				}
			});
			task.setOnFailed(new EventHandler<WorkerStateEvent>() {

				@Override
				public void handle(WorkerStateEvent event) {
					showWaitingDialog(false);
				}
			});
			new Thread(task).start();
		}
	}

	private void showWaitingDialog(boolean b) {
		scanButton.setDisable(b);
		folderChooserDialogButton.setDisable(b);

		Stage stage = (Stage) scanButton.getScene().getWindow();
		if (b) {
			infoBox1 = infoBox("Scanning started", "Scanning for viruses...", null, infoBox1);
			stage.setTitle(MainApp.VIRUS_TOTAL_FOLDER_ANALYZER + "- Scanning for viruses...");
		} else {
			if (infoBox1 != null && infoBox1.isShowing()) {
				infoBox1.close();
				infoBox2 = infoBox("Scanning completed", "Scanning for viruses...", null, infoBox2);
			}
			stage.setTitle(MainApp.VIRUS_TOTAL_FOLDER_ANALYZER);
		}

	}

	private static Alert infoBox(String infoMessage, String titleBar, String headerMessage, Alert infoBox) {
		infoBox = new Alert(AlertType.INFORMATION);
		infoBox.setTitle(titleBar);
		infoBox.setHeaderText(headerMessage);
		infoBox.setContentText(infoMessage);
		infoBox.showAndWait();
		return infoBox;
	}

	private void fillTableViewWithResult(List<ScannerVirusResult> scanFolderResult) {
		folderTable.getItems().clear();

		final ObservableList<ScannerVirusResult> data = FXCollections.observableArrayList(scanFolderResult);

		folderTable.getColumns().get(0).setCellValueFactory(new PropertyValueFactory<>("filePath"));
		folderTable.getColumns().get(1).setCellValueFactory(new PropertyValueFactory<>("hash"));
		folderTable.getColumns().get(2).setCellValueFactory(new PropertyValueFactory<>("scanned"));
		folderTable.getColumns().get(3).setCellValueFactory(new PropertyValueFactory<>("infection"));
		folderTable.getColumns().get(4).setCellValueFactory(new PropertyValueFactory<>("type"));

		folderTable.setItems(data);
	}

}
