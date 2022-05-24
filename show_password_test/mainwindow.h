#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTcpServer>
#include <QTcpSocket>
#include <QLabel>
#include <QDateTime>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    QByteArray cipher_text1;//用于接收子线程1的密文
    QByteArray plain_text1;//用于接收子线程1的明文
    QString time1;//用于接收子线程1的时间
    QTcpServer* my_server=new QTcpServer(this);//创建服务器对象



private:
    Ui::MainWindow *ui;
    //QTcpServer* my_server;//添加指针以创建对象
    //QTcpSocket* my_socket;
    QLabel* current_connect_status;


signals:
    //void send_socket(QTcpSocket my_socket);//把服务器得到的套接字发送给子线程
    //void recv_ciphertext(QByteArray cipher_text1);//接收子线程发过来的密文
    //void recv_plaintext(QByteArray plain_text1);//接收子线程发过来的明文
    //void recv_time(QDateTime time1);//接收子线程发过来的时间
};

#endif // MAINWINDOW_H
