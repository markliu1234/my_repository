#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QTcpSocket>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    my_server = new QTcpServer(this);//3:创建服务器对象
    ui->port->setText("8989");//4:设置一个默认的端口号8989
    current_connect_status = new QLabel;//14:创建一个用于显示连接状态的label对象
    ui->statusbar->addWidget(current_connect_status);//15:将label对象设置到窗口的状态栏中去
    setWindowTitle("server");

    connect(my_server,&QTcpServer::newConnection,this,[=]()
    {
        my_socket=my_server->nextPendingConnection();//8:当有新连接时服务器端会发出newConnection信号，接收到信号后就建立一个用于通信的套接字对象,声明在头文件类的定义中
        current_connect_status->setText("connect succeed");//16:当连接成功时用文字显示
        connect(my_socket,&QTcpSocket::readyRead,this,[=]()
        {
            QByteArray data = my_socket->readAll();//9:当套接字发出一个readyRead信号时，说明数据已全部到达，此时可以通过readAll读出全部数据
            ui->record->append("client:"+data);//10:将接收到的数据显示到界面中去
        });
        connect(my_socket,&QTcpSocket::disconnected,this,[=]()
        {
            my_socket->close();
            my_socket->deleteLater();//17：释放套接字对象，自动销毁
            current_connect_status->setText("connect failed");//18:当套接字发出一个disconnected信号时说明断开了连接，此时用文字显示
        });
    });
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_start_listen_clicked()
{
    unsigned short port = ui->port->text().toUShort();//5：获得端口号并转换字符类型为无符号短整型
    my_server->listen(QHostAddress::Any,port);//6:服务器对象通过listen设置监听，ip地址设为默认的本地ip地址，端口就用上面的port
    ui->start_listen->setDisabled(true);//7:开始监听后就设置"开始监听"按钮为不可用状态
}

void MainWindow::on_send_msg_clicked()
{
    QString msg= ui->server_msg->toPlainText();//11:将服务器端要发送给客户端的文本以纯文本的形式读取出来，保存到msg中
    my_socket->write(msg.toUtf8());//12:将文本写入内存中，由套接字进行发送(转换成QByteArrey类型)
    ui->record->append("server:"+msg);//13:将发送的数据显示到界面中去
}
