#include "psdthread.h"
#include <QTcpServer>
#include <QTcpSocket>
#include <QLabel>
#include "mainwindow.h"
#include <QDebug>
#include "des.h"
PsdThread1::PsdThread1(QTcpSocket* my_socket,QObject *parent) : QThread(parent)
{
     my_socket1=my_socket;//接收主线程中的套接字
}

void PsdThread1::run()//重写run函数功能，用于接收从其它端发来的密文并调用解密函数解密
{
    connect(my_socket1,&QTcpSocket::readyRead,this,[=]()
    {
        qDebug("可以读");
        QByteArray data1;//用于保存readAll所读出的数据
        data1 = my_socket1->readAll();//当套接字发出一个readyRead信号时，说明数据已全部到达，此时可以通过readAll读出全部数据
        qDebug(data1);
        QByteArray ciphered_text1=(encrypt(data1)).toLocal8Bit();//调用加密函数进行加密，传入参数为readAll所读出的数据data1，返回值为加密后的密文ciphered_text
        QByteArray plained_text1=(decrypt(ciphered_text1)).toLocal8Bit();//调用解密函数进行解密，传入参数为加密后的密文ciphered_text，返回值为解密后的明文plained_text1
        emit send_ciphertext1(ciphered_text1);//将加密后的密文作为信号发射出去给主线程
        emit send_plaintext1(plained_text1);//将解密后的明文作为信号发射出去给主线程
        qDebug(ciphered_text1);
        qDebug(plained_text1);
    });
    /*如果服务结束就调用下面的代码关闭套接字服务
    my_socket1->close();
    my_socket1->deleteLater();
    emit over();*/
    exec();
}

QString PsdThread1::encrypt(QByteArray data1)//加密函数
{
    QString data=QString::fromLocal8Bit(data1);//转换格式
    QString Qkey="12345678";//设置测试密码
    QString err="input error";
    /*if(data.length()!=8)
    {
           qDebug(err);//控制台报错

    }*/
    char *key = Qkey.toLatin1().data();
    Des->setKey(key);
    Des->encrypt(data.toLatin1().data());//调用加密算法函数
    QString endata = QString::fromLocal8Bit(Des->endata.c_str());
    return endata;
}

QString PsdThread1::decrypt(QByteArray data1)//解密函数
{
    QString data=QString::fromLocal8Bit(data1);//转换格式
    QString Qkey="12345678";//设置测试密码
    QString err="input error";
    /*if(data.length()!=8)
    {
           qDebug(err);//控制台报错
    }*/
    char *key = Qkey.toLatin1().data();
    Des->setKey(key);
    Des->decrypt(data.toLatin1().data());//调用解密算法函数
    QString dedata = QString::fromLocal8Bit(Des->dedata.c_str());
    return dedata;
}
