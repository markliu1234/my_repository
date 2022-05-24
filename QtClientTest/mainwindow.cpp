#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QTcpSocket>
#include <QHostAddress>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->port->setText("8000");//4:设置一个默认的端口号8989
    ui->ip->setText("127.0.0.1");//设置一个默认的ip地址（这里设为本地ip）
    current_connect_status = new QLabel;//14:创建一个用于显示连接状态的label对象
    ui->statusbar->addWidget(current_connect_status);//15:将label对象设置到窗口的状态栏中去
    ui->disconnect_to_server->setDisabled(true);//一开始将断开连接按钮设为不可用
    setWindowTitle("client");

    my_socket = new QTcpSocket(this);//实例化套接字对象
    connect(my_socket,&QTcpSocket::readyRead,this,[=]()
    {
         QByteArray data = my_socket->readAll();//9:当套接字发出一个readyRead信号时，说明数据已全部到达，此时可以通过readAll读出全部数据
         ui->record->append("server:"+data);//10:将接收到的数据显示到界面中去
     });

     connect(my_socket,&QTcpSocket::disconnected,this,[=]()
     {
         my_socket->close();
         my_socket->deleteLater();//17：释放套接字对象，自动销毁
         current_connect_status->setText("connect failed");//18:当套接字发出一个disconnected信号时说明断开了连接，此时用文字显示
         ui->connect_to_server->setDisabled(false);//连接断开后将连接按钮设为可用
         ui->disconnect_to_server->setDisabled(true);//连接断开后将断开连接按钮设为不可用
     });

     connect(my_socket,&QTcpSocket::connected,this,[=]()
     {
           current_connect_status->setText("connect succeed");//16:当连接成功时用文字显示
           ui->connect_to_server->setDisabled(true);//连接成功后将连接按钮设为不可用
           ui->disconnect_to_server->setDisabled(false);//连接成功后将断开连接按钮设为可用

     });
 }
MainWindow::~MainWindow()
{ 
    delete ui;
}

void MainWindow::on_send_msg_clicked()
{
    QString msg= ui->client_msg->toPlainText();//11:将服务器端要发送给客户端的文本以纯文本的形式读取出来，保存到msg中
    my_socket->write(msg.toUtf8());//12:将文本写入内存中，由套接字进行发送(转换成QByteArrey类型)
    ui->record->append("client:"+msg);//13:将发送的数据显示到界面中去
}

void MainWindow::on_connect_to_server_clicked()
{
    QString ip = ui->ip->text();
    unsigned short port = ui->port->text().toUShort();//5：获得端口号并转换字符类型为无符号短整型
    my_socket->connectToHost(QHostAddress(ip),port);//套接字根据端口号和ip信息连接服务器
}

void MainWindow::on_disconnect_to_server_clicked()
{
    my_socket->close();//套接字断开连接
    ui->connect_to_server->setDisabled(false);//连接断开后将连接按钮设为可用
    ui->disconnect_to_server->setDisabled(true);//连接断开后将断开连接按钮设为不可用
    current_connect_status->setText("connect failed");//18:当套接字发出一个disconnected信号时说明断开了连接，此时用文字显示
}
