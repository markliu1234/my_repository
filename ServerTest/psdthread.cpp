#include "psdthread.h"
#include <QTcpServer>
#include <QTcpSocket>
#include <QLabel>
#include <QDebug>
#include "des.h"
PsdThread1:: PsdThread1(QByteArray datap,bool b,QObject *parent) : QThread(parent)
{
     my_QThread=new QThread;//新建一个线程
     a=b;
     data=datap;
}

void PsdThread1::run()//重写run函数功能，用于接收从其它端发来的密文并调用解密函数解密
{
    if(a)
    {
        QByteArray ciphered_text1=(encrypt(data)).toLocal8Bit();//调用加密函数进行加密，传入参数为readAll所读出的数据data1，返回值为加密后的密文ciphered_text
        emit send_ciphertext1(ciphered_text1);//将加密后的密文作为信号发射出去给主线程
    }
    else
    {
        QByteArray plained_text1=(decrypt(data)).toLocal8Bit();//调用解密函数进行解密，传入参数为加密后的密文ciphered_text，返回值为解密后的明文plained_text1
        emit send_plaintext1(plained_text1);//将解密后的明文作为信号发射出去给主窗口
    }
    //    connect(my_QThread,SIGNAL(finished()),my_QThread,SLOT(deleteLater()));//线程结束后摧毁
    my_QThread->deleteLater();

}

QString PsdThread1::encrypt(QByteArray data1)//加密函数
{
    QString data=QString::fromLocal8Bit(data1);//转换格式
    char *key = Qkey.toLatin1().data();
    Des->setKey(key);
    Des->encrypt(data.toLatin1().data());//调用解密算法函数
    QString endata = QString::fromLocal8Bit(Des->endata.c_str());
    return endata;
}

QString PsdThread1::decrypt(QByteArray data1)//解密函数
{
    QString data=QString::fromLocal8Bit(data1);//转换格式
    char *key = Qkey.toLatin1().data();
    Des->setKey(key);
    Des->decrypt(data.toLatin1().data());//调用解密算法函数
    QString dedata = QString::fromLocal8Bit(Des->dedata.c_str());
    return dedata;
}
