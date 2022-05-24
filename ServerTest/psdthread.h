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
    explicit PsdThread1(QByteArray datap,bool b,QObject *parent = nullptr);//加入一个套接字传入参数
    QString encrypt(QByteArray data);//加密函数,传入明文，传出密文
    QString decrypt(QByteArray data);//解密函数,传入密文，传出明文
    QByteArray data;//用于保存readAll所读出的数据
    bool a;
    QString Qkey="12345678";//设置测试密码


protected:
    void run() override;//重写run函数

private:
    QThread *my_QThread;//
    DesCrypt* Des = new DesCrypt();//用于进行des解密的对象

signals:
    void send_ciphertext1(QByteArray data1);//自定义一个信号用于把密文从子线程发送到主线程
    void send_plaintext1(QByteArray plained_text1);//自定义一个信号用于把明文从子线程发送到主线程
    void send_time1(QDateTime);//自定义一个信号用于把接收时间发送到主线程
    void over();//子线程结束信号

public slots:
};

#endif // PSDTHREAD_H
