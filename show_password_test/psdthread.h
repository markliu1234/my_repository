#ifndef PSDTHREAD_H
#define PSDTHREAD_H

#include <QThread>
#include <QTcpServer>
#include <QTcpSocket>
#include <QLabel>
#include <QDateTime>
#include "des.h"

class PsdThread1 : public QThread
{
    Q_OBJECT
public:
    explicit PsdThread1(QTcpSocket* my_socket,QObject *parent = nullptr);//加入一个套接字传入参数
    QString encrypt(QByteArray data);//加密函数,传入明文，传出密文
    QString decrypt(QByteArray data);//解密函数,传入密文，传出明文
    //void get_socket(QTcpSocket);//用于接收主线程发过来的套接字对象
    //QByteArray data1;//用于保存readAll所读出的数据
    //QByteArray plained_text1;//用于保存解密后的明文
    QDateTime *subthread1_time;//用于保存接收时间

protected:
    void run() override;//重写run函数

private:
    QTcpSocket *my_socket1;//用于接收主线程传过来的套接字
    DesCrypt* Des = new DesCrypt();//用于进行des解密的对象

signals:
    void send_ciphertext1(QByteArray data1);//自定义一个信号用于把密文从子线程发送到主线程
    void send_plaintext1(QByteArray plained_text1);//自定义一个信号用于把明文从子线程发送到主线程
    //void send_time1(QDateTime);//自定义一个信号用于把接收时间发送到主线程
    void over();//子线程结束信号

public slots:
};

#endif // PSDTHREAD_H
