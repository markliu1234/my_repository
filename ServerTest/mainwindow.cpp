#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "mythread1.h"
#include <QTcpServer>
#include <QTcpSocket>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    /************设置ip和端口号*************/
    unsigned short port = 8000;//指定一个端口号
    my_server->listen(QHostAddress::Any,port);//服务器对象通过listen设置监听，ip地址设为默认的本地ip地址，端口就用上面的port
    /************有新连接则开启子线程*************/
    connect(my_server,&QTcpServer::newConnection,this,[=]()
    {
        QTcpSocket* my_socket = my_server->nextPendingConnection();//当有新连接时服务器端会发出newConnection信号，接收到信号后就建立一个用于通信的套接字对象,声明在头文件类的定义中
        MyThread1* subthread1 = new MyThread1(my_socket);//有新连接就在主线程中创造一个子线程对象,并把数据库和套接字对象传给子线程
        subthread1->start();//随后启动子线程

        /************判断用户登陆类型要用到的槽函数*************/
        connect(subthread1,&MyThread1::send_login_auth,this,[=](int auth_type)
        {
            login_auth=auth_type;//获取子线程中的登录用户的类型
        });
        connect(subthread1,&MyThread1::get_login_auth,this,[=]()
        {
            emit login_auth_info(login_auth);//主线程将用户登录类型通过信号发送给子线程
        });
        connect(this,&MainWindow::login_auth_info,subthread1,MyThread1::login_auth);//主线程通过信号发送用户登录类型给子线程后，子线程调用函数进行接收

        /************获取用户id要用到的槽函数*************/
        connect(subthread1,&MyThread1::send_login_id,this,[=](QString userid)
        {
            uid=userid;//获取子线程中的登录用户的id
        });
        connect(subthread1,&MyThread1::get_login_id,this,[=]()
        {
            emit uid_info(uid);//主线程将用户id通过信号发送给子线程
        });
        connect(this,&MainWindow::uid_info,subthread1,MyThread1::userid);//主线程通过信号发送用户id给子线程后，子线程调用函数进行接收

        /************按指定路径存储文件要用到的槽函数*************/
        connect(subthread1,&MyThread1::send_path,this,[=](QString file_path)
        {
            file_save_path=file_path;//获取子线程中的文件存储路径
        });
        connect(subthread1,&MyThread1::get_path,this,[=]()
        {
            emit file_path_info(file_save_path);//主线程将文件位置信息通过信号发送给子线程
        });
        connect(this,&MainWindow::file_path_info,subthread1,MyThread1::path);//主线程通过信号发送文件位置信息给子线程后，子线程调用函数进行接收

        /************销毁线程资源的槽函数*************/
        connect(subthread1,&MyThread1::over,this,[=]()//子线程如果发来over信号则销毁线程资源
        {
           subthread1->exit();
           subthread1->wait();
           subthread1->deleteLater();
        });

    });
}

MainWindow::~MainWindow()
{
    delete ui;
}
