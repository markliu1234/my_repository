#ifndef MYTHREAD1_H
#define MYTHREAD1_H

#include <QThread>
#include <QSqlDatabase>
#include <QTcpSocket>
#include"mystruct.h"
#include"psdthread.h"

class MyThread1 : public QThread
{
    Q_OBJECT
public:
    explicit MyThread1(QTcpSocket *my_socket1, QObject *parent = nullptr);

    void login_auth(QString);//接收主线程传过来的用户登录类型信息
    int auth;//用于接收主线程信号中的用户登录类型信息
    void userid(QString);//接收主线程传过来的用户id信息
    int login_id;//用于接收主线程信号中的用户id信息
    void path(QString);//接收主线程传过来的文件存储路径
    QString fpath;//用于接收主线程信号中的位置信息

    int num=0;
    QString ip;
    QByteArray ba;
    QSqlDatabase db;
    QString auth;//客户端登录的用户类型

signals:
    void send_login_auth(int);//客户端登录时用于判断登陆的时管理员还是普通员工，将此身份信息发送给主线程
    void send_path(QString);//员工上传文件前，选择存储位置时，通过此信号将位置信息发送给主线程
    void send_login_id(QString);//客户端成功登录时，将用户id发送给主线程
    void get_login_auth();//子线程在用户使用功能前先获取用户登录的类型(是管理员or用户登录)
    void get_login_id();//子线程请求获取用户登录的id
    void get_path();//子线程在接收文件前向主线程发送此信号用于获取存储位置信息
    void over();//子线程结束信号

private:
    QTcpSocket *my_socket1;//用于接收主线程传过来的套接字

protected:
    void run() override;

public slots:
};

#endif // MYTHREAD1_H
