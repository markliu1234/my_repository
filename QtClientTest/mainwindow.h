#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTcpSocket>//1:包含头文件(记得先在pro中加上network模块)
#include <QLabel>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:

    void on_send_msg_clicked();

    void on_connect_to_server_clicked();

    void on_disconnect_to_server_clicked();

private:
    Ui::MainWindow *ui;
    QTcpSocket* my_socket;//2:添加指针以创建对象
    QLabel* current_connect_status;
};
#endif // MAINWINDOW_H
