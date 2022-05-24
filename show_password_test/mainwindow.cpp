#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QTcpServer>
#include <QTcpSocket>
#include <QLabel>
#include <QDateTime>
#include "psdthread.h"//将子线程的头文件包含到主线程中
#include <QDebug>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    //my_server=new QTcpServer(this);//创建服务器对象
    current_connect_status;//文字控件对象
    unsigned short port = 8000;//指定一个端口号
    my_server->listen(QHostAddress::Any,port);//服务器对象通过listen设置监听，ip地址设为默认的本地ip地址，端口就用上面的port
    connect(my_server,&QTcpServer::newConnection,this,[=]()
    {
        QTcpSocket* my_socket=my_server->nextPendingConnection();//当有新连接时服务器端会发出newConnection信号，接收到信号后就建立一个用于通信的套接字对象,声明在头文件类的定义中
        PsdThread1* subthread1 = new PsdThread1(my_socket);//有新连接就在主线程中创造一个子线程对象,并把套接字传给子线程
        //emit send_socket(my_socket);//服务器如果检测到有新连接就将套接字信号发送出去给子线程
        subthread1->start();//随后启动子线程
        connect(subthread1,&PsdThread1::send_ciphertext1,this,[=](QByteArray data1)//子线程发出传递密文的信号后，主线程进行接收
        {
            ui->cipher_text1->clear();//每次接收到密文时先清空文本框
            cipher_text1=data1;
            ui->cipher_text1->setText(QString::fromLocal8Bit(cipher_text1));//展示密文
        });
        connect(subthread1,&PsdThread1::send_plaintext1,this,[=](QByteArray plained_text1)//子线程发出传递明文的信号后，主线程调用信号进行接收
        {
            ui->plain_text1->clear();//每次接收到密文时先清空文本框
            plain_text1=plained_text1;
            ui->plain_text1->setText(QString::fromLocal8Bit(plain_text1));//展示明文
        });
        connect(subthread1,&PsdThread1::over,this[=]()//子线程如果发来over信号则销毁线程资源
        {
           subthread1->exit();
           subthread1->wait();
           subthread1->deleteLater();
        });
    });
}

/*void MainWindow::recv_time(QDateTime subthread1_time)
    {
        time1 = subthread1_time.toString("hh:mm:ss");
        ui->text_time1->setPlainText(" ");//每次接收到明文时先清空文本框
    }*/

MainWindow::~MainWindow()
{
    delete ui;
}
