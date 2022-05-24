#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTcpServer>//1:包含头文件(记得先在pro中加上network模块)
#include <QTcpSocket>
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
    void on_start_listen_clicked();
    void on_send_msg_clicked();

private:
    Ui::MainWindow *ui;
    QTcpServer* my_server;//2:添加指针以创建对象
    QTcpSocket* my_socket;
    QLabel* current_connect_status;

signals:
    void send_socket(QTcpSocket);//把通信得到的套接字发送给子线程
};
#endif // MAINWINDOW_H
