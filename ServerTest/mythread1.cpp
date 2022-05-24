#include "mythread1.h"
#include "mystruct.h"
#include <QThread>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSqlDatabase>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QTime>
#include <QDebug>
#include <QMessageBox>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QList>

MyThread1::MyThread1(QTcpSocket *my_socket,QObject *parent) : QThread(parent)
{
    my_socket1=my_socket;
    /************连接数据库*************/
    db = QSqlDatabase::addDatabase("QMYSQL");
    db.setHostName("localhost");//写自己的数据库
    db.setPort(3306);
    db.setDatabaseName("su");
    db.setUserName("root");
    db.setPassword("thelastofus123");
    bool ok = db.open();
    if(ok){
        qDebug()<<"成功连接数据库";
    }
    else{
        QMessageBox::warning(NULL,"警告","无法连接数据库");
    }

}

void MyThread1::run()
{
    qDebug()<<"子线程已经启动";
    QSqlQuery query;
    //接收到数据
    connect(my_socket1,&QTcpSocket::readyRead,this,[=]()
    {
        QByteArray recdata=my_socket1->readAll();
        qDebug(recdata);
        QStringList recvStrList1=QString(recdata).split("]");
        //        QList<qintptr> socketList1;
        //        QStringList  head;//发送给服务器的数据包串
        //        QStringList  msg;//发送给服务器的数据包
        if(num<1)
        {
            //            说明这是收到一个证书，证书可以直接解包，是明文。后面就是证书验证++ 验证成功，把自己的证书发给客户端
            //        检测是不是认证阶段的报文
            //        确实只有num>=1的时候，才是认证阶段之后
            //        认证阶段发过来的是明文包，所以可以直接解包
            QStringList head1=QString(recvStrList1.at(0)).split(",");
            if(head1.at(1)=="5")
            {
                if(head1.at(2)=="1")
                {
                    //这两个if满足说明是认证阶段的证书包
                    //可以进行哈希值认证，此处要进行证书合法性验证，后期加上，现阶段只根据用户的公钥和证书序列号来判断

                    //提取证书到msg1,并分段到certificate1
                    QStringList msg1=QString(recvStrList1.at(1)).split(",");
                    QStringList certificate1=QString(msg1.at(2)).split("$");
                    if(msg1.at(5)=="1.0")
                    {
                        //验证公钥--可以发现，应该要加一个ip验证，不然在服务器处理的时候，又来了同一用户的请求，会出现麻烦
                        if(ip==head1.at(5))//暂时ip是在数据包头部的5这个地方
                        {
                            qDebug("请勿重复发送证书请求");
                            return;
                        }
                        //                            //使用md5算法对双方都有的内容进行哈希变换,得到结果一，保存在m.ciphertext中
                        //                            MD5 m;
                        //                            m.Encrypt("D:/ProgramFiles(x86)/sidaijie/WorkSpace/QT/QT/cript/rsa.txt");
                        //                            //使用公钥实现加密部分的数字签名的解密，得到公钥的哈希值//一开始顺序是NED，因为这里解密的流程，用的是rsa对象里面的私钥，所以赋值的时候，把私钥的位置放上公钥的值就行了
                        //                            BigInt strN(QString(certificate1.at(0)).toStdString(), 16);
                        //                            BigInt strE(QString(certificate1.at(1)).toStdString(), 16);
                        //                            BigInt strD("39E75F3757C1A40A87493AA67EDB38B7BD31954FF184BD24698A66309CED1B7A0C423D0799D42B96815D7A8009EC5F4CB66628E9657004995FDFB5865B10C3F9", 16);
                        //                            string sttr=QString(recvStrList1.at(2)).toStdString();
                        //                            strN.sign=true;
                        //                            strE.sign=true;
                        //                            strD.sign=true;
                        //                            //        RSA(const BigInt& N, const BigInt& E, const BigInt& D): key(N, E, D) {}
                        //                            RSA *rsa1 = new RSA(strN, strD, strE);//这里就是私钥的位置放上了公钥
                        //                            rsa1->key.digNum = 256;
                        //                            StringTrans st(sttr, strN.GetBitLength() - 17);//数字签名部分

                        //                            rsa1->decrypt(st);//
                        //                            string result1=st.toString();
                        //                            string result2=m.ciphertext;
                        //                            if(result1==result2)
                        //                            {
                        //                                qDebug("认证成功");
                        //                                num++;
                        //                            }
                        //                            else
                        //                            {
                        //                                qDebug("认证失败");
                        //                                //并且返回一个失败的报文给客户端
                        //                                //                        。。。
                        //                            }
                        num++;
                    }
                    else
                    {
                        qDebug("认证失败，证书版本号错误！");
                    }
                }
            }
            QString msg="";
            //生成自己的证书，从文件读取证书的部分项目，最后加入上面生成的数字签名
            Certificate* certificate = new Certificate();
            QString PKB=QString::fromStdString("提取公钥");//提取公钥
            QDateTime dt =QDateTime::currentDateTime();//当前系统时间
            msg+=dt.toString("yyyy.MM.dd hh:mm:ss.zzz")+",";
            msg+=certificate->deadline = QString::fromStdString("hfyfyj");//证书的截止日期从文件获取
            msg+=certificate->pk = PKB+",";//公钥
            msg+=certificate->name = "localName,";//拥有者
            msg+=certificate->serial = "0,";//版本号
            msg+=certificate->version = "1.0";//序列号
            //证书构造完毕
        }
        else
        {
            //返回的报文内容
            QString replymsg="";
            //接收到一个加密的密文,用des进行解密
            //创建子进程进行解密，指定窗口父对象，用于显示密文内容
            PsdThread1* subthread1 = new PsdThread1(recdata,false,this);
            subthread1->start();//随后启动子线程
            //接收到已完成密文解密信号，进入数据包解包阶段
            connect(subthread1,&PsdThread1::send_plaintext1,this,[=](QByteArray plained_text1)
            {
                ba=plained_text1;
                qDebug(ba);//打印出解密后的明文

                QStringList recvStrList=QString(ba).split("]");
                QStringList head=QString(recvStrList.at(0)).split(",");
                QStringList msg=QString(recvStrList.at(1)).split(",");

                if(head.at(1)=="5")//说明是客户端发给服务器端的
                {
                    if(head.at(2)=="1")//用户登录
                    {
                        msg=QString(recvStrList1.at(1)).split(",");
                        qDebug()<<"用户准备进行登录";
                        bool success;//用于判断登录是否成功
                        /************接收个人信息*************/
                        QString uid=msg.at(0);//用户名，即uid
                        QString psswd=msg.at(1);//密码
                        QString auth_type=msg.at(2);//用户类型(是管理员还是员工)
                        emit send_login_auth(auth_type);//将用户类型发送给主线程
                        /************判断是否是已注册用户*************/
                        QString judge=QString("select Uid from users");
                        query.exec(judge);//如果是数据表中已有Uid的记录则直接登陆失败，反之则检查密码是否正确
                        QStringList user_id_list;
                        while (query.next())
                        {
                            user_id_list.push_back(query.value(0).toString());//遍历所有的uid
                        }
                        int temp=0;//用于判断是否有相同id
                        for(int i=0;i<user_id_list.size();i++)
                        {
                            qDebug()<<"已有的uid有:"<<user_id_list.at(i);//控制台输出已有的uid
                            if(uid==user_id_list.at(i))//说明已有此人信息，则进行检查密码是否正确
                            {
                                /************查看账号和密码是否正确*************/
                                QString check_login=QString("select Psswd from users where Uid='%1'").arg(uid);
                                query.exec(check_login);
                                query.next();
                                if((query.value(0).toString())!=psswd)
                                {
                                    success=0;
                                    qDebug("密码不正确，登陆失败");
                                    break;
                                }
                                else
                                {
                                    success=1;
                                    qDebug("密码正确，登陆成功");
                                    emit send_login_id(uid);//把用户id通过信号发送给主线程
                                }
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(check_login);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                temp=uid.toInt();
                                break;
                            }
                            /***********发送报文给客户端*************/
                            //这是用于下一次通信的des密钥
                            QString descrypto="";
                            //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                            //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                            QString replyhead="";
                            //定义数据包头部
                            FunctionBox *functionbox=new FunctionBox();
                            replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                            replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                            if(success)
                            {
                                replyhead+=functionbox->Function_pack_type="1,";//功能包类型,代表登录成功
                            }
                            else
                            {
                                replyhead+=functionbox->Function_pack_type="2,";//功能包类型,代表登录失败
                            }
                            replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                            QDateTime current_date_time =QDateTime::currentDateTime();
                            QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                            replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                            // head+=functionbox-> Ack;//Ack
                            //head+=functionbox-> Status_code;//状态码
                            //head+=functionbox-> Extend;//保留字段
                            replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                            replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                            //定义报文主体部分
                            replymsg+=" ,"
                            //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                            QString message=replyhead+"]"+replymsg+"]"+descrypto;
                            qDebug()<<message;
                            //发送请求报文（明文发送）
                            ba=message.toUtf8();
                            qint64 basize=ba.size();
                            my_socket1->write(QString(ba).toStdString().c_str(),basize);
                            my_socket1->flush();
                            /***********关闭服务并发送结束信号*************/
                            db.close();
                            my_socket1->close();
                            my_socket1->deleteLater();
                            emit over();
                        }
                        if(temp==0)//说明此用户还没注册
                        {
                            qDebug("此用户未注册");
                        }

                    }
                    else//用户功能实现
                    {
                        emit get_login_auth();//先向主线程发送该信号,请求获得用户登录类型的信息
                        //判断是用户登录还是管理员登录，用户登录为0，管理员登陆为1
                        /***********普通员工端功能*************/
                        if(auth==0)
                        {
                            if(head.at(2)=="2")//待遇查询
                            {
                                qDebug("员工请求查询待遇");
                                emit get_login_id();//向主线程发送信号请求获得用户id信息
                                bool success;//用于判断是否成功
                                /************查询任务信息*************/
                                QString search_wage=QString("select Level,Clock_in_times,Bonus,Commission,Wage from users where Uid='%1'").arg(login_id);
                                query.exec(search_wage);
                                success=query.exec(search_wage);
                                /************封装待遇信息*************/
                                query.next();
                                QStringList wage_info;
                                for(int i=0;i<5;i++)
                                {
                                    wage_info.push_back(query.value(i).toString());
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="3,";//功能包类型,代表返回待遇数据
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表未找到待遇数据
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<5;i++)
                                {
                                    replymsg+=wage_info.at(i)+",";//等级,签到次数，考勤奖金，项目提成，基本工资
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="3")//查询任务
                            {
                                qDebug("员工请求查询任务");
                                bool success;//用于判断是否成功
                                /************查询任务信息*************/
                                QString search_task=("select Tid,Content,Ttime from tasks");
                                query.exec(search_task);
                                success=query.exec(search_task);
                                /************封装任务信息*************/
                                query.next();
                                QStringList task_info;
                                while (query.next())
                                {
                                    for(int i=0;i<3;i++)
                                    {
                                        task_info.push_back(query.value(i).toString());
                                    }
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="4,";//功能包类型,代表返回任务数据
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表未找到任务数据
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<3;i++)
                                {
                                    replymsg+=task_info.at(i)+",";//任务号，任务内容，截止时间
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                                //                            int currentRow = ui->tableWidget->rowCount();
                                //                            ui->tableWidget->insertRow(currentRow);
                                //                            QTableWidgetItem *item = new QTableWidgetItem();
                                //                            QTableWidgetItem *item_2 = new QTableWidgetItem();
                                //                            QTableWidgetItem *item_3 = new QTableWidgetItem();
                                //                            QStringList taskcontent;

                                //                            int i=task.count();/////////此处可能有bug
                                //                            int j=0;
                                //                            while(i>0)
                                //                            {
                                //                                taskcontent=QString(task.at(j)).split(",");
                                //                                j++;i--;
                                //                                item->setText(taskcontent.at(0));
                                //                                item_2->setText(taskcontent.at(1));
                                //                                item_3->setText(taskcontent.at(2));
                                //                                ui->tableWidget->setItem(currentRow, 0, item);
                                //                                ui->tableWidget->setItem(currentRow, 1, item_2);
                                //                                ui->tableWidget->setItem(currentRow, 2, item_3);
                                //                            }

                            }
                            else
                            if(head.at(2)=="4")//上传任务进度
                            {
                                qDebug("员工请求上传任务进度");
                                bool success;//用于判断是否成功
                                /************接收任务信息*************/
                                QString tid=msg.at(0);//任务号
                                int status=QString(msg.at(1)).toInt();//任务完成情况(未完成为0，已完成为1)
                                /************更新任务信息*************/
                                QString update_task_info=QString("update task set Status='%1' where Tid='%2'").arg(status).arg(tid);
                                query.exec(update_task_info);
                                success=query.exec(update_task_info);
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(update_task_info);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                db.close();
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="5,";//功能包类型,代表任务进度数据接收成功
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表任务进度数据未接收成功
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                replymsg+=" ,"
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="5")//签到
                            {
                                qDebug("员工进行签到");
                                emit get_login_id();//向主线程发送信号请求获得用户id信息
                                bool success;//用于判断是否成功
                                /************更新签到信息*************/
                                QDateTime time=&QDateTime::currentDateTime();
                                QString clock_in=QString("update users set Clock_in_time_today='%1',Clock_in_times=Clock_in_times+1 where Uid='%2'").arg(time).arg(login_id);
                                query.exec(clock_in);
                                success=query.exec(clock_in);
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(clock_in);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                /************封装签到信息*************/
                                QString clock_in_info=QString("select Name,Clock_in_time_today from users where Uid='%1'").arg(login_id);
                                query.exec(clock_in_info);
                                query.next();
                                QStringList clock_info;
                                while (query.next())
                                {
                                    for(int i=0;i<2;i++)
                                    {
                                        clock_info.push_back(query.value(i).toString());
                                    }
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="6,";//功能包类型,代表返回签到数据
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表签到失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<2;i++)
                                {
                                    replymsg+=clock_info.at(i)+",";//打卡人，打卡时间
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="6")//下载文件(访问文件列表)
                            {
                                qDebug("员工访问文件列表");
                                bool success;//用于判断是否成功
                                /************查询文件列表*************/
                                QString search_file_info=("select Fname,EXtime,Fsize,Founder from files");
                                query.exec(search_file_info);
                                success=query.exec(search_file_info);
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(search_file_info);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                /************封装文件信息*************/
                                query.next();
                                QStringList file_info;
                                while (query.next())
                                {
                                    for(int i=0;i<4;i++)
                                    {
                                        file_info.push_back(query.value(i).toString());
                                    }
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="7,";//功能包类型,代表返回签到数据
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表签到失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<4;i++)
                                {
                                    replymsg+=file_info.at(i)+",";//文件名，修改时间，大小，创建人
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="7")//下载文件
                            {
                                msg=QString(recvStrList1.at(1)).split(",");
                                qDebug()<<"用户准备下载文件";
                                bool success=0;//用于判断是否成功
                                /************接收文件名*************/
                                QString fname=msg.at(0);//文件名
                                /************在文件列表中找到文件保存路径*************/
                                QString search_file_path=QString("select Fpath from files where Fname='%1'").arg(fname);
                                query.exec(search_file_path);
                                query.next();
                                QString file_path=query.value(0).toString();//得到对应文件的存储位置
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(search_file_path);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                /************根据路径找到文件信息并进行封装*************/
                                QString file_info=QString("select Fname,EXtime,Fsize,Founder from files where Fname='%1'").arg(fname);
                                query.exec(file_info);
                                query.next();
                                QStringList file_info_list;
                                for(int i=0;i<4;i++)
                                {
                                    file_info_list.push_back(query.value(i).toString());
                                }
                                /************根据路径找到文件并进行封装*************/
                                QFile file(file_path);
                                QFileInfo info(file_path);
                                int file_size=info.size();//文件的总大小
                                file.open(QFile::ReadOnly);//文件的打开方式设为只读
                                while (!file.atEnd())
                                {
                                    static int num=0;
                                    if(num==0)
                                    {
                                        my_socket1->write((char*)&file_size, 4);//如果是第一次循环就先把文件大小发送出去
                                    }
                                    QByteArray line = file.readLine();//如果文件没读完就一行一行的往后读
                                    num+=line.size();//没发送一次数据就更新一次数据大小
                                    //int percent=(num*100/file_size);//记录文件下载的进度
                                    my_socket1->write(line);//把这行数据通过套接字发送给服务器
                                    success=1;//用于判断是否成功
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="8,";//功能包类型,代表传回文件本体
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表文件传输失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<4;i++)
                                {
                                    replymsg+=file_info_list.at(i)+",";//文件名，修改时间，大小，创建人
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="8")//上传文件(请求存储位置)
                            {
                                msg=QString(recvStrList1.at(1)).split(",");
                                qDebug()<<"用户请求文件存储位置";
                                bool success=1;//用于判断是否成功
                                /************接收文件信息*************/
                                QString file_name=msg.at(0);//所选定的文件名字
                                QString file_path=msg.at(1);//所选定的文件存储位置
                                /************判断存储位置是否可用*************/
                                QString judge_path=("select Fpath from files");
                                QStringList name_list;
                                QStringList path_list;
                                query.exec(judge_path);
                                query.next();
                                while (query.next())
                                {
                                    for(int i=0;i<2;i++)
                                    {
                                        name_list.push_back(query.value(0).toString());//遍历所有的文件名
                                        path_list.push_back(query.value(1).toString());//遍历所有的存储路径
                                        //判断是否有是否有同名文件，如果有，则是否有重复的路径，两样都重复则不能上传
                                        if(name_list(i)!=file_name)
                                        {
                                            emit send_path(file_path);//将路径通过信号发送给主线程
                                        }
                                        else if(path_list(i)!=file_path)
                                        {
                                            emit send_path(file_path);//将路径通过信号发送给主线程
                                        }
                                        else
                                        {
                                            success=0;
                                            break;
                                        }
                                    }
                                }
                                /************根据路径找到文件并进行封装*************/
                                QFile file(file_path);
                                QFileInfo info(file_path);
                                int file_size=info.size();//文件的总大小
                                file.open(QFile::ReadOnly);//文件的打开方式设为只读
                                while (!file.atEnd())
                                {
                                    static int num=0;
                                    if(num==0)
                                    {
                                        my_socket1->write((char*)&file_size, 4);//如果是第一次循环就先把文件大小发送出去
                                    }
                                    QByteArray line = file.readLine();//如果文件没读完就一行一行的往后读
                                    num+=line.size();//没发送一次数据就更新一次数据大小
                                    //int percent=(num*100/file_size);//记录文件下载的进度
                                    my_socket1->write(line);//把这行数据通过套接字发送给服务器
                                    success=1;//用于判断是否成功
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="9,";//功能包类型,代表允许使用此路径
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表申请存储路径失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                replymsg=" ,";
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="9")//上传文件本体
                            {
                                emit get_path();//子线程向主线程发送信号申请获取文件存储位置信息
                                msg=QString(recvStrList1.at(1)).split(",");
                                qDebug()<<"用户准备下载文件";
                                bool success=0;//用于判断是否成功
                                /************接收新文件的信息*************/
                                QString fname=msg.at(0);//文件名
                                QDateTime ftime=&QDateTime::fromString(msg.at(1));//修改时间
                                QString fsize=msg.at(2);//大小
                                QString founder=msg.at(3);//创建人
                                QString save_path=fpath;//文件路径(通过信号从主线程中获得)
                                /************将新文件的信息存入数据库*************/
                                QString insert_file_info=QString("insert into files(Fname,EXtime,Fsize,Founder,Fpath) values('%1','%2','%3','%4','%5')").arg(fname).arg(ftime).arg(fsize).arg(founder).arg(save_path);
                                query.exec(insert_file_info);
                                qDebug()<<"已更新文件信息";
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(insert_file_info);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                /************读取文件信息*************/
                                QFile* file = new QFile(fpath);//fpath通过path函数得到主线程通过信号传过来的文件存储路径
                                file->open(QFile::WriteOnly);
                                static int count = 0;//统计文件接收了多少
                                static int total = 0;//在第一次循环时获取文件大小信息
                                if(count == 0)
                                {
                                    my_socket1->read((char*)&total, 4);
                                }
                                // 读出剩余的数据
                                QByteArray all = my_socket1->readAll();
                                count += all.size();
                                file->write(all);
                                /************判断数据是否接收完了*************/
                                if(count == total)
                                {
                                    qDebug()<<"文件信息已经接收完成";
                                    success=1;
                                    //my_socket1->close();
                                    //my_socket1->deleteLater();
                                    //file->close();
                                    //file->deleteLater();
                                    //emit over();
                                }
                                /************查询文件列表*************/
                                QString search_file_info=QString("select Fname,EXtime,Fsize,Founder from files where Fname='%1' and Fpath='%2'").arg(fname).arg(fpath);
                                query.exec(search_file_info);
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(search_file_info);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                /************封装文件信息*************/
                                query.next();
                                QStringList file_info;
                                for(int i=0;i<4;i++)
                                {
                                    file_info.push_back(query.value(i).toString());//文件名，创建时间，大小，创建人
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="10,";//功能包类型,代表文件上传成功
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type="11,";//功能包类型,代表文件上传失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<4;i++)
                                {
                                    replymsg+=file_info.at(i)+",";//文件名，创建时间，大小，创建人
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                file->close();
                                file->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="10")//个人信息访问
                            {
                                qDebug()<<"用户请求访问个人信息";
                                emit get_login_id();//向主线程发送信号请求获得用户id信息
                                bool success;//用于判断是否成功
                                /************查找个人信息*************/
                                QString search_user_info=QString("select Uid,Name,Sex,Birthday,qq,vx,Phone,Email,Nation,Political,Department,Wage,Personal_id from where Uid='%1'").arg(login_id);//所选定的个人信息
                                query.exec(search_user_info);
                                success=query.exec(search_user_info);
                                /************查找个人信息*************/
                                query.next();
                                QStringList user_info;
                                for(int i=0;i<13;i++)
                                {
                                    user_info.push_back(query.value(i).toString());
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="10,";//功能包类型,代表个人信息访问成功
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表签到失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<13;i++)
                                {
                                    replymsg+=user_info.at(i)+",";//工号，姓名，性别，生日，qq,微信，电话，邮箱，民族，政治面貌，部门，意向薪资，身份证号
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="11")//个人信息修改
                            {
                                msg=QString(recvStrList1.at(1)).split(",");
                                qDebug()<<"准备将修改个人信息";
                                emit get_login_id();//向主线程发送信号请求获得用户id信息
                                bool success;//用于判断是否成功
                                /************接收个人信息*************/
                                QString uid=msg.at(0);//员工id
                                QString birthday=msg.at(3);//出生日期
                                QString phone=msg.at(6);//电话
                                QString email=msg.at(7);//邮箱
                                QString department=msg.at(10);//部门
                                QString id=msg.at(12);//身份证号
                                QString name=msg.at(1);//姓名
                                QString nation=msg.at(8);//民族
                                QString political=msg.at(9);//政治面貌
                                QString qq=msg.at(4);//qq号
                                QString sex=msg.at(2);//性别
                                QString vx=msg.at(5);//微信号
                                QString wage=msg.at(11);//意向薪资
                                /************判断是插入还是更新*************/
                                QString judge=QString("select Uid from users");
                                query.exec(judge);//如果是数据表中已有Uid的记录，则进行更新，反之则插入
                                QStringList user_id_list;
                                while (query.next())
                                {
                                    user_id_list.push_back(query.value(0).toString());//遍历所有的uid
                                }
                                int temp=0;//用于判断是否有相同id
                                for(int i=0;i<user_id_list.size();i++)
                                {
                                    qDebug()<<"已有的uid有:"<<user_id_list.at(i);//控制台输出已有的uid
                                    if(login_id==user_id_list.at(i))//说明已有此人信息，则进行更新而不是插入
                                    {
                                        /************更新个人信息*************/
                                        QString update_info=QString("update users set Name='%2',Birthday='%3',Email='%4',Department='%5',Personal_id='%6',Nation='%7',Polotical='%8',qq='%9',Sex='%10',vx='%11',Wage='%12',Phone='%13' where Uid='%1'").arg(login_id).arg(name).arg(birthday).arg(email).arg(department).arg(id).arg(nation).arg(political).arg(qq).arg(sex).arg(vx).arg(wage).arg(phone);
                                        success=query.exec(update_info);
                                        bool flag = query.exec(update_info);
                                        if(flag)
                                        {
                                            qDebug()<<"已更新";
                                        }
                                        /************创建事务*************/
                                        db.transaction();
                                        bool flag1 = query.exec(update_info);
                                        if (flag1)
                                        {
                                            db.commit();
                                        }
                                        else
                                        {
                                            db.rollback();
                                        }
                                        temp=uid.toInt();
                                        break;
                                    }
                                }
                                if(temp==0)//说明没更新
                                {
                                    /************插入个人信息*************/
                                    QString insert_info = QString("insert into users(Uid,Name,Birthday,Email,Department,Personal_id,Nation,Polotical,qq,Sex,vx,wage) values('%1','%2','%3','%4','%5','%6','%7','%8','%9','%10','%11','%12')").arg(login_id).arg(name).arg(birthday).arg(email).arg(department).arg(id).arg(nation).arg(political).arg(qq).arg(sex).arg(vx).arg(wage);
                                    success=query.exec(insert_info);
                                    bool flag=query.exec(insert_info);
                                    if(flag)
                                    {
                                        qDebug()<<"已插入";
                                    }
                                    /************创建事务*************/
                                    db.transaction();
                                    bool flag1 = query.exec(insert_info);
                                    if (flag1)
                                    {
                                        db.commit();
                                    }
                                    else
                                    {
                                        db.rollback();
                                    }
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="11,";//功能包类型,代表个人信息修改成功
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表个人信息修改失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                replymsg=" ,";
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                        }

                        /***********管理员端功能*************/
                        else
                        {
                            if(head.at(2)=="10")//个人信息操作
                            {
                                msg=QString(recvStrList1.at(1)).split(",");
                                //                    msg+=ui->EmployerID->text()+",";0
                                //                    msg+=ui->stuBirthday->text()+",";1
                                //                    msg+=ui->stuCall->text()+",";2
                                //                    msg+=ui->stuEmail->text()+",";3
                                //                    msg+=ui->stuHobby->text()+",";4
                                //                    msg+=ui->stEmployerIDcard->text()+",";5
                                //                    msg+=ui->stuName->text()+",";6
                                //                    msg+=ui->stuNation->text()+",";7
                                //                    msg+=ui->stuPolitical->currentText()+",";8
                                //                    msg+=ui->stuqq->text()+",";9
                                //                    msg+=ui->stuSex->currentText()+",";10
                                //                    msg+=ui->stuWeixin->text()+",";11

                                qDebug()<<"准备将个人信息写入数据库";
                                bool success;//用于判断是否成功
                                /************接收个人信息*************/
                                QString uid=msg.at(0);//员工id
                                QString birthday=msg.at(1);//出生日期
                                QString phone=msg.at(2);//电话
                                QString email=msg.at(3);//邮箱
                                QString department=msg.at(4);//部门
                                QString id=msg.at(5);//身份证号
                                QString name=msg.at(6);//姓名
                                QString nation=msg.at(7);//民族
                                QString political=msg.at(8);//政治面貌
                                QString qq=msg.at(9);//qq号
                                QString sex=msg.at(10);//性别
                                QString vx=msg.at(11);//微信号

                                /************判断是插入还是更新*************/
                                QString judge=QString("select Uid from users");
                                query.exec(judge);//如果是数据表中已有Uid的记录，则进行更新，反之则插入
                                QStringList user_id_list;
                                while (query.next())
                                {
                                    user_id_list.push_back(query.value(0).toString());//遍历所有的uid
                                }
                                int temp=0;//用于判断是否有相同id
                                for(int i=0;i<user_id_list.size();i++)
                                {
                                    qDebug()<<"已有的uid有:"<<user_id_list.at(i);//控制台输出已有的uid
                                    if(uid==user_id_list.at(i))//说明已有此人信息，则进行更新而不是插入
                                    {
                                        /************更新个人信息*************/
                                        QString update_info=QString("update users set Name='%2',Birthday='%3',Email='%4',Department='%5',Personal_id='%6',Nation='%7',Polotical='%8',qq='%9',Sex='%10',vx='%11',Phone='%12' where Uid='%1'").arg(uid).arg(name).arg(birthday).arg(email).arg(department).arg(id).arg(nation).arg(political).arg(qq).arg(sex).arg(vx).arg(phone);
                                        success=query.exec(update_info);
                                        bool flag = query.exec(update_info);
                                        if(flag)
                                        {
                                            qDebug()<<"已更新";
                                        }
                                        /************创建事务*************/
                                        db.transaction();
                                        bool flag1 = query.exec(update_info);
                                        if (flag1)
                                        {
                                            db.commit();
                                        }
                                        else
                                        {
                                            db.rollback();
                                        }
                                        temp=uid.toInt();
                                        break;
                                    }
                                }
                                if(temp==0)//说明没更新
                                {
                                    /************插入个人信息*************/
                                    QString insert_info = QString("insert into users(Uid,Name,Birthday,Email,Department,Personal_id,Nation,Polotical,qq,Sex,vx) values('%1','%2','%3','%4','%5','%6','%7','%8','%9','%10','%11')").arg(uid).arg(name).arg(birthday).arg(email).arg(department).arg(id).arg(nation).arg(political).arg(qq).arg(sex).arg(vx);
                                    bool flag=query.exec(insert_info);
                                    success=query.exec(insert_info);
                                    if(flag)
                                    {
                                        qDebug()<<"已插入";
                                    }
                                    /************创建事务*************/
                                    db.transaction();
                                    bool flag1 = query.exec(insert_info);
                                    if (flag1)
                                    {
                                        db.commit();
                                    }
                                    else
                                    {
                                        db.rollback();
                                    }
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="10,";//功能包类型,代表个人信息修改成功
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表个人信息修改失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                replymsg+=" ,";
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="11")//全体员工概览(工号)
                            {
                                msg=QString(recvStrList1.at(1)).split(",");
                                qDebug()<<"准备根据工号查询员工信息";
                                bool success;//用于判断是否成功
                                /************接收工号*************/
                                QString uid=msg.at(0);//工号
                                /************根据工号查询个人信息*************/
                                QString uid_search_info=QString("select Uid,Department,Personal_id,Phone,Birthday,Political from users where Uid='%1'").arg(uid);
                                query.exec(uid_search_info);
                                success=query.exec(uid_search_info);
                                /************封装个人信息*************/
                                query.next();
                                QStringList user_info;
                                for(int i=0;i<6;i++)
                                {
                                    user_info.push_back(query.value(i).toString());
                                }
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(uid_search_info);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="11,";//功能包类型,代表返回要筛选的员工信息
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表个人信息修改失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<6;i++)
                                {
                                    replymsg+=user_info.at(i);//工号，部门，身份证号，手机号，出生日期，政治面貌
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="12")//全体员工概览(部门号)
                            {
                                msg=QString(recvStrList1.at(1)).split(",");
                                qDebug()<<"准备根据部门号查询员工信息";
                                bool success;//用于判断是否成功
                                /************接收部门号*************/
                                QString department=msg.at(0);//部门号
                                /************根据部门号查询个人信息*************/
                                QString department_search_info=QString("select Uid,Department,Personal_id,Phone,Birthday,Political from users where Department='%1'").arg(department);
                                query.exec(department_search_info);
                                success=query.exec(department_search_info);
                                /************封装个人信息*************/
                                query.next();
                                QStringList user_info;
                                int row=0;//用于统计有几行数据
                                while (query.next())
                                {
                                    for(int i=0;i<6;i++)
                                    {
                                        user_info.push_back(query.value(i).toString());
                                    }
                                    row++;
                                }
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(department_search_info);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="11,";//功能包类型,代表返回要筛选的员工信息
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表个人信息修改失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<6*row;i++)
                                {
                                    replymsg+=user_info.at(i);//工号，部门，身份证号，手机号，出生日期，政治面貌
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="13")//全体员工概览(姓名)
                            {
                                msg=QString(recvStrList1.at(1)).split(",");
                                qDebug()<<"准备根据姓名查询员工信息";
                                 bool success;//用于判断是否成功
                                /************接收姓名*************/
                                QString name=msg.at(0);//姓名
                                /************根据工号查询个人信息*************/
                                QString name_search_info=QString("select Uid,Department,Personal_id,Phone,Birthday,Political from users where Name='%1'").arg(name);
                                query.exec(name_search_info);
                                success=query.exec(name_search_info);
                                /************封装个人信息*************/
                                query.next();
                                QStringList user_info;
                                int row=0;//用于统计有几行数据
                                while (query.next())
                                {
                                    for(int i=0;i<6;i++)
                                    {
                                        user_info.push_back(query.value(i).toString());
                                    }
                                    row++;
                                }
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(name_search_info);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="11,";//功能包类型,代表返回要筛选的员工信息
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表个人信息修改失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<6*row;i++)
                                {
                                    replymsg+=user_info.at(i);//工号，部门，身份证号，手机号，出生日期，政治面貌
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="14")//删除离职员工
                            {
                                msg=QString(recvStrList1.at(1)).split(",");
                                qDebug()<<"准备根据工号删除员工信息";
                                bool success;//用于判断是否成功
                                /************接收工号*************/
                                QString uid=msg.at(0);//工号
                                /************根据工号查询个人信息*************/
                                QString uid_search_info=QString("select Uid,Department,Personal_id,Phone,Birthday,Political from users where Uid='%1'").arg(uid);
                                query.exec(uid_search_info);
                                success=query.exec(uid_search_info);
                                /************封装个人信息*************/
                                query.next();
                                QStringList user_info;
                                for(int i=0;i<6;i++)
                                {
                                    user_info.push_back(query.value(i).toString());
                                }
                                /************根据工号删除个人信息*************/
                                QString uid_delete_info=QString("delete from users where Uid='%1'").arg(uid);
                                query.exec(uid_delete_info);
                                success=query.exec(uid_delete_info);
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(uid_delete_info);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="14,";//功能包类型,代表离职员工信息删除成功
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type="15,";//功能包类型,代表离职员工信息删除失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<6;i++)
                                {
                                    replymsg+=user_info.at(i);//工号，部门，身份证号，手机号，出生日期，政治面貌
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="15")//上传任务
                            {
                                msg=QString(recvStrList1.at(1)).split(",");
                                qDebug()<<"准备上传任务";
                                bool success;//用于判断是否成功
                                /************接收任务信息*************/
                                QString tid=msg.at(0);//任务号
                                QString department=msg.at(1);//部门号
                                QDateTime time=QDateTime::fromString(msg.at(2),"yyyy-MM-dd hh:mm:ss");//截止时间
                                QString content=msg.at(3);//任务内容
                                /************判断是插入还是更新*************/
                                QString judge=QString("select Tid from tasks");
                                query.exec(judge);//如果是数据表中已有Tid的记录，则进行更新，反之则插入
                                QStringList task_id_list;
                                while (query.next())
                                {
                                    task_id_list.push_back(query.value(0).toString());//遍历所有的tid
                                }
                                int temp=0;//用于判断是否有相同id
                                for(int i=0;i<task_id_list.size();i++)
                                {
                                    qDebug()<<"已有的tid有:"<<user_id_list.at(i);//控制台输出已有的yid
                                    if(tid==task_id_list.at(i))//说明已有此人信息，则进行更新而不是插入
                                    {
                                        /************更新任务信息*************/
                                        QString update_info=QString("update tasks set Department='%2',Ttime='%3',Content='%4' where Tid='%1'").arg(tid).arg(department).arg(time).arg(content);
                                        query.exec(update_info);
                                        success=query.exec(update_info);
                                        bool flag = query.exec(update_info);
                                        if(flag)
                                        {
                                            qDebug()<<"已更新";
                                        }
                                        /************创建事务*************/
                                        db.transaction();
                                        bool flag1 = query.exec(update_info);
                                        if (flag1)
                                        {
                                            db.commit();
                                        }
                                        else
                                        {
                                            db.rollback();
                                        }
                                        temp=tid.toInt();
                                        break;
                                    }
                                }
                                if(temp==0)//说明没更新
                                {
                                    /************插入任务信息*************/
                                    QString insert_info = QString("insert into tasks(Tid,Department,Ttime,Content) values('%1','%2','%3','%4')").arg(tid).arg(department).arg(time).arg(content);
                                    query.exec(insert_info);
                                    success=query.exec(insert_info);
                                    bool flag=query.exec(insert_info);
                                    if(flag)
                                    {
                                        qDebug()<<"已插入";
                                    }
                                    /************创建事务*************/
                                    db.transaction();
                                    bool flag1 = query.exec(insert_info);
                                    if (flag1)
                                    {
                                        db.commit();
                                    }
                                    else
                                    {
                                        db.rollback();
                                    }
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="16,";//功能包类型,代表任务上传成功
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type="17,";//功能包类型,代表任务上传失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                replymsg+=" ,";
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="16")//所有任务列表
                            {
                                bool success;//用于判断是否成功
                                /************查看任务列表*************/
                                QString check_all_tasks=("select * from tasks");
                                query.exec(check_all_tasks);
                                success=query.exec(check_all_tasks);
                                /************封装任务信息*************/
                                query.next();
                                QStringList task_list;
                                int row=0;//用于统计有几行数据
                                while(query.next())
                                {
                                    for(int i=0;i<5;i++)
                                    {
                                        task_list.push_back(query.value(i).toString());
                                    }
                                    row++;
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="18,";//功能包类型,代表返回任务库列表成功
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表返回任务库列表失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<5*row;i++)
                                {
                                    replymsg+=task_list.at(i);//任务号，部门(参与组)，截止时间，任务内容，完成情况
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="17")//已完成任务
                            {
                                bool success;//用于判断是否成功
                                /************查看任务列表*************/
                                QString check_finished_tasks=("select * from tasks where Status=1");
                                query.exec(check_finished_tasks);
                                success=query.exec(check_finished_tasks);
                                /************封装任务信息*************/
                                query.next();
                                QStringList task_list;
                                int row=0;//用于统计有几行数据
                                while(query.next())
                                {
                                    for(int i=0;i<5;i++)
                                    {
                                        task_list.push_back(query.value(i).toString());
                                    }
                                    row++;
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="18,";//功能包类型,代表返回任务库列表成功
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表返回任务库列表失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<5*row;i++)
                                {
                                    replymsg+=task_list.at(i);//任务号，部门(参与组)，截止时间，任务内容，完成情况
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="18")//未完成任务
                            {
                                bool success;//用于判断是否成功
                                /************查看任务列表*************/
                                QString check_unfinished_tasks=("select * from tasks where Stastus=0");
                                query.exec(check_unfinished_tasks);
                                success=query.exec(check_unfinished_tasks);
                                /************封装任务信息*************/
                                query.next();
                                QStringList task_list;
                                int row=0;//用于统计有几行数据
                                while(query.next())
                                {
                                    for(int i=0;i<5;i++)
                                    {
                                        task_list.push_back(query.value(i).toString());
                                    }
                                    row++;
                                }
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="18,";//功能包类型,代表返回任务库列表成功
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type=" ,";//功能包类型,代表返回任务库列表失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<5*row;i++)
                                {
                                    replymsg+=task_list.at(i);//任务号，部门(参与组)，截止时间，任务内容，完成情况
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                            else
                            if(head.at(2)=="19")//删除任务
                            {
                                bool success;//用于判断是否成功
                                msg=QString(recvStrList1.at(1)).split(",");
                                qDebug()<<"准备根据任务号删除员工信息";
                                /************接收任务号*************/
                                QString tid=msg.at(0);//任务号
                                /************根据任务号查询任务信息*************/
                                QString tid_search_info=QString("select * from tasks where Tid='%1'").arg(tid);
                                query.exec(tid_search_info);
                                /************封装任务信息*************/
                                query.next();
                                QStringList task_info;
                                while (query.next())
                                {
                                    for(int i=0;i<6;i++)
                                    {
                                        task_info.push_back(query.value(i).toString());
                                    }
                                }
                                /************创建事务*************/
                                db.transaction();
                                bool flag1 = query.exec(tid_search_info);
                                if (flag1)
                                {
                                    db.commit();
                                }
                                else
                                {
                                    db.rollback();
                                }
                                db.close();
                                /************根据任务号删除任务信息*************/
                                QString tid_delete_info=QString("delete from tasks where Tid='%1'").arg(tid);
                                query.exec(tid_delete_info);
                                success=query.exec(tid_delete_info);
                                /***********发送报文给客户端*************/
                                //这是用于下一次通信的des密钥
                                QString descrypto="";
                                //如果上面的所有结果是成功的，说明成功完成了用户信息的录入
                                //以下是解包过程完成后，构造发送的数据报文的头部headmsg
                                QString replyhead="";
                                //定义数据包头部
                                FunctionBox *functionbox=new FunctionBox();
                                replyhead+=functionbox->Group_feature_code="16,";//小组特征码，即组号,我们是第16组
                                replyhead+=functionbox->Packet_type="6,";//数据包类型，6代表是服务器发给客户端的
                                if(success)
                                {
                                    replyhead+=functionbox->Function_pack_type="19,";//功能包类型,代表返回任务删除成功
                                }
                                else
                                {
                                    replyhead+=functionbox->Function_pack_type="20,";//功能包类型,代表返回任务删除失败
                                }
                                replyhead+=functionbox->Encoding_type="utf8,";//编码类型,设置为utf8
                                QDateTime current_date_time =QDateTime::currentDateTime();
                                QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz");//获取当前时间
                                replyhead+=functionbox->Time_stamp= current_date+",";//时间戳
                                // head+=functionbox-> Ack;//Ack
                                //head+=functionbox-> Status_code;//状态码
                                //head+=functionbox-> Extend;//保留字段
                                replyhead+=functionbox->Sender_IP="192.168.53.112,";//发送者ip，即本机的ip地址
                                replyhead+=functionbox->Receiver_IP="192.168.53.112,";//接收者ip，即客户端的ip地址
                                //定义报文主体部分
                                for(int i=0;i<5*row;i++)
                                {
                                    replymsg+=task_list.at(i);//任务号，部门(参与组)，截止时间，任务内容，完成情况
                                }
                                //报文：头部+分隔符+报文主体部分+分隔符+数字签名
                                QString message=replyhead+"]"+replymsg+"]"+descrypto;
                                qDebug()<<message;
                                //发送请求报文（明文发送）
                                ba=message.toUtf8();
                                qint64 basize=ba.size();
                                my_socket1->write(QString(ba).toStdString().c_str(),basize);
                                my_socket1->flush();
                                /***********关闭服务并发送结束信号*************/
                                db.close();
                                my_socket1->close();
                                my_socket1->deleteLater();
                                emit over();
                            }
                        }
                    }
                }
                else
                {
                    //说明head.at(0)不是5
                }
            });
        }
    });
    exec();//事件循环
}

void MyThread1::login_auth(int login_auth)
{
    auth=login_auth;
    qDebug(login_auth);
}

void MyThread1::userid(int uid)
{
    login_id=uid;
    qDebug(login_id);
}

void MyThread1::path(QString file_save_path)
{
    fpath=file_save_path;
    qDebug(fpath);
}

//                //        list<<"001"<<"005"<<"010";//本地测试数据

//                /***********服务器端的功能实现*************/
//                if(head.at(1)=="5")//数据包编号，说明是client传给server的
//                {
//                    //管理员部分的功能
//                    if(head.at(2)=="000")//特征码，说明是client端是管理员,则下面是管理员的功能实现
//                    {
//                        if(head.at(2)=="10")//个人信息操作，功能包编号
//                        {
                            //                    msg=QString(recvStrList1.at(1)).split(",");
                            //                    msg+=ui->EmployerID->text()+",";0
                            //                   msg+=ui->stuBirthday->text()+",";1
                            //                   msg+=ui->stuCall->text()+",";2
                            //                   msg+=ui->stuEmail->text()+",";3
                            //                   msg+=ui->stuHobby->text()+",";4
                            //                    msg+=ui->stEmployerIDcard->text()+",";5
                            //                   msg+=ui->stuName->text()+",";6
                            //                   msg+=ui->stuNation->text()+",";7
                            //                   msg+=ui->stuPolitical->currentText()+",";8
                            //                   msg+=ui->stuqq->text()+",";9
                            //                   msg+=ui->stuSex->currentText()+",";10
                            //                   msg+=ui->stuWeixin->text()+",";11

                            //                    qDebug()<<"准备将个人信息写入数据库";
                            //                    QStringList buf;
                            //                    buf<<"1005"<<"aa"<<"val1919"<<"20181001986"<<"1"<<"4978976884@qq.com"<<"8800"<<"0"<<"224"<<"fb";
                            //                    /************接收个人信息*************/
                            //                    QString EmployerID=msg.at(0);
                            //                    QString Userid=EmployerID.toInt();//员工id
                            //                    QString Birthday=msg.at(1);//出生日期
                            //                    QString Call=msg.at(2);//电话
                            //                    QString Email=msg.at(3);
                            //                    QString Hobby=msg.at(4);//部门meng
                            //                    QString EmployerIDcard=msg.at(5);//身份证号
                            //                    QString Name=msg.at(6);
                            //                    QString Nation=msg.at(7);//
                            //                    QString Political=msg.at(8);
                            //                    QString qq=msg.at(9);
                            //                    QString Sex=msg.at(10);
                            //                    QString Weixin=msg.at(11);

                            //                    /************判断是插入还是更新*************/
                            //                    QString judge=QString("select EmployerID from users");
                            //                    query.exec(judge);//如果是数据表中已有EmployerID的记录，则进行更新，反之则插入
                            //                    QStringList user_id_list;
                            //                    while (query.next())
                            //                    {
                            //                        user_id_list.push_back(query.value(0).toString());//遍历所有的EmployerID
                            //                    }
                            //                    int temp=0;//用于判断是否有相同id
                            //                    for(int i=0;i<user_id_list.size();i++)
                            //                    {
                            //                        qDebug()<<"已有的EmployerID有:"<<user_id_list.at(i);//控制台输出已有的EmployerID
                            //                        if(Userid==user_id_list.at(i))//说明已有此人信息，则进行更新而不是插入
                            //                        {
                            //                            /************更新个人信息*************/
                            //                            QString update_info=QString("update users set Name='%2',Psswd='%3',Phone='%4',Sign='%5',Email='%6',Wage='%7',gender='%8',Apart_num='%9',Department='%10' where EmployerID='%1'").arg(Userid).arg(name).arg(password).arg(phone).arg(sign).arg(email).arg(wage).arg(gender).arg(apart_num).arg(department);
                            ////                            query.exec(update_info);
                            //                            bool flag = query.exec(update_info);
                            //                            if(flag)
                            //                            {
                            //                                qDebug()<<"已更新";
                            //                            }
                            //                            /************创建事务*************/
                            //                            db.transaction();
                            //                            bool flag1 = query.exec(update_info);
                            //                            if (flag1)
                            //                            {
                            //                                db.commit();
                            //                            }
                            //                            else
                            //                            {
                            //                                db.rollback();
                            //                            }
                            //                            temp=Userid.toInt();
                            //                            db.close();
                            //                            break;
                            //                        }

                            //                    }
                            //                    if(temp==0)//说明没更新
                            //                    {
                            //                        /************插入个人信息*************/
                            //                        QString insert_info = QString("insert into users(EmployerID,Name,Psswd,Phone,Sign,Email,Wage,gender,Apart_num,Department) values('%1','%2','%3','%4','%5','%6','%7','%8','%9','%10')").arg(Userid).arg(name).arg(password).arg(phone).arg(sign).arg(email).arg(wage).arg(gender).arg(apart_num).arg(department);
                            //                        query.exec(insert_info);
                            //                        qDebug()<<"已插入";
                            //                        /************创建事务*************/
                            //                        db.transaction();
                            //                        bool flag1 = query.exec(insert_info);
                            //                        if (flag1)
                            //                        {
                            //                            db.commit();
                            //                        }
                            //                        else
                            //                        {
                            //                            db.rollback();
                            //                        }
                            //                        db.close();
                            //                    }
//                        }
                        //                else
                        //                if(head.at(2)=="11")//全体员工概览(工号)，功能包编号
                        //                {
                        //                    QStringList buf;
                        //                    buf<<"1003";
                        //                    qDebug()<<"准备根据工号查看员工信息";
                        //                    /************接收工号信息*************/
                        //                    QString EmployerID=buf.at(0);
                        //                    int Userid=EmployerID.toInt();//员工id
                        //                    QString EmployerID_search=QString("select EmployerID from users");
                        //                    query.exec(EmployerID_search);
                        //                    QList<qint32> user_id_list;//储存所有的EmployerID用于遍历
                        //                    while (query.next())
                        //                    {
                        //                        qDebug()<<(query.value(0)).toUInt();
                        //                        user_id_list.push_back((query.value(0)).toInt());//遍历所有的EmployerID
                        //                    }
                        //                    qDebug()<<"遍历结束";
                        //                    QStringList EmployerID_search_info_list;//储存所查找的EmployerID的用户的个人信息用于遍历
                        //                    int temp=0;//用于判断是否有相同id
                        //                    for(int i=0;i<user_id_list.size();i++)
                        //                    {
                        //                        if(Userid==user_id_list.at(i))
                        //                        {
                        //                            /************封装找到的个人信息*************/
                        //                            QString record_user_info;
                        //                            for(int j=0;j<10;j++)
                        //                            {
                        //                                record_user_info=QString("select * from users where EmployerID='%1'").arg(Userid);//选出所找到用户的那一行
                        //                                query.exec(record_user_info);//此时query是停留在第一条数据之前，后面必须用next往后查询，否则会出错
                        //                                query.next();
                        //                                EmployerID_search_info_list.push_back(query.value(j).toString());//把所找到的用户的数据保存进容器中
                        //                            }
                        //                            qDebug()<<"已找到工号对应的员工信息";
                        //                            /************创建事务*************/
                        //                            db.transaction();
                        //                            bool flag1 = query.exec(record_user_info);
                        //                            if (flag1)
                        //                            {
                        //                                db.commit();
                        //                            }
                        //                            else
                        //                            {
                        //                                db.rollback();
                        //                            }
                        //                            /************控制台输出查找结果*************/

                        //                            for(int i=0;i<10;i++)
                        //                            {
                        //                                qDebug()<<EmployerID_search_info_list.at(i);
                        //                            }

                        //                            temp=Userid;
                        //                            db.close();
                        //                            break;
                        //                        }
                        //                    }
                        //                    if(temp==0)
                        //                    {
                        //                        qDebug()<<"未找到对应员工记录";
                        //                        db.close();
                        //                    }
                        //                }
                        //                if(list.at(2)=="012")//全体员工概览(部门号)，功能包编号
                        //                {
                        //                    QStringList buf;
                        //                    buf<<"ne";
                        //                    qDebug()<<"准备根据部门号查看员工信息";
                        //                    /************接收工号信息*************/
                        //                    QString depart=buf.at(0);
                        //                    //char *department;//部门
                        //                    //department=depart.toLatin1().data();
                        //                    QString department_search=QString("select Department from users");
                        //                    query.exec(department_search);
                        //                    QStringList department_list;//储存所有的部门用于遍历
                        //                    while (query.next())
                        //                    {
                        //                        department_list.push_back((query.value(0)).toString());//遍历所有的部门号
                        //                    }
                        //                    QStringList department_search_info_list;//储存所查找的部门号的用户的个人信息用于遍历
                        //                    QString temp;//用于判断是否有相同id
                        //                    for(int i=0;i<department_list.size();i++)
                        //                    {
                        //                        qDebug()<<department_list.at(i);
                        //                        if(depart==department_list.at(i))
                        //                        {
                        //                            /************封装找到的个人信息*************/
                        //                            QString record_user_info;
                        //                            for(int j=0;j<10;j++)
                        //                            {
                        //                                record_user_info=QString("select * from users where Department='%1'").arg(depart);//选出所找到用户的那一行
                        //                                query.exec(record_user_info);//此时query是停留在第一条数据之前，后面必须用next往后查询，否则会出错
                        //                                query.next();
                        //                                department_search_info_list.push_back(query.value(j).toString());//把所找到的用户的数据保存进容器中
                        //                            }
                        //                            qDebug()<<"已找到部门号对应的员工信息";
                        //                            /************创建事务*************/
                        //                            db.transaction();
                        //                            bool flag1 = query.exec(record_user_info);
                        //                            if (flag1)
                        //                            {
                        //                                db.commit();
                        //                            }
                        //                            else
                        //                            {
                        //                                db.rollback();
                        //                            }
                        //                            /************控制台输出查找结果*************/

                        //                            for(int i=0;i<10;i++)
                        //                            {
                        //                                qDebug()<<department_search_info_list.at(i);
                        //                            }

                        //                            temp=depart;
                        //                            db.close();
                        //                            break;
                        //                        }
                        //                    }
                        //                    if(temp!=depart)
                        //                    {
                        //                        qDebug()<<"未找到对应员工记录";
                        //                        db.close();
                        //                    }
                        //                }
                        //                if(list.at(2)=="013")//全体员工概览(姓名)，功能包编号
                        //                {
                        //                    QStringList buf;
                        //                    buf<<"he";
                        //                    qDebug()<<"准备根据姓名查看员工信息";
                        //                    /************接收姓名信息*************/
                        //                    QString name=buf.at(0);
                        //                    QString name_search=QString("select Name from users");
                        //                    query.exec(name_search);
                        //                    QStringList name_list;//储存所有的姓名用于遍历
                        //                    while (query.next())
                        //                    {
                        //                        name_list.push_back(query.value(0).toString());//遍历所有的姓名
                        //                    }
                        //                    QStringList name_search_info_list;//储存所查找的部门号的用户的个人信息用于遍历
                        //                    QString temp;//用于判断是否有相同id
                        //                    for(int i=0;i<name_list.size();i++)
                        //                    {
                        //                        qDebug()<<name_list.at(i);
                        //                        if(name==name_list.at(i))
                        //                        {
                        //                            /************封装找到的个人信息*************/
                        //                            QString record_user_info;
                        //                            for(int j=0;j<10;j++)
                        //                            {
                        //                                record_user_info=QString("select * from users where Name='%1'").arg(name);//选出所找到用户的那一行
                        //                                query.exec(record_user_info);
                        //                                query.next();
                        //                                name_search_info_list.push_back(query.value(j).toString());//把所找到的用户的数据保存进容器中
                        //                            }
                        //                            qDebug()<<"已找到姓名对应的员工信息";
                        //                            /************创建事务*************/
                        //                            db.transaction();
                        //                            bool flag1 = query.exec(record_user_info);
                        //                            if (flag1)
                        //                            {
                        //                                db.commit();
                        //                            }
                        //                            else
                        //                            {
                        //                                db.rollback();
                        //                            }
                        //                            /************控制台输出查找结果*************/
                        //                            for(int i=0;i<10;i++)
                        //                            {
                        //                                qDebug()<<name_search_info_list.at(i);
                        //                            }

                        //                            temp=name;
                        //                            db.close();
                        //                            break;
                        //                        }
                        //                    }
                        //                    if(temp!=name)
                        //                    {
                        //                        qDebug()<<"未找到对应员工记录";
                        //                        db.close();
                        //                    }
                        //                }
                        //                if(list.at(2)=="014")//删除离职员工，功能包编号
                        //                {
                        //                    QStringList buf;
                        //                    buf<<"1005"<<"aa"<<"val1919"<<"20181001986"<<"1"<<"4978976884@qq.com"<<"8800"<<"0"<<"224"<<"fb";
                        //                    qDebug()<<"成功连接数据库";

                        //                    /************接收个人信息*************/
                        //                    QString EmployerID=buf.at(0);
                        //                    int Userid=EmployerID.toInt();//员工id
                        //                    QString uname=buf.at(1);
                        //                    char *name;//姓名
                        //                    name=uname.toLatin1().data();
                        //                    QString pwd=buf.at(2);
                        //                    char*password;
                        //                    password=pwd.toLatin1().data();//密码
                        //                    QString phone=buf.at(3);//电话
                        //                    QString usign=buf.at(4);
                        //                    int sign = usign.toInt();//权限
                        //                    QString uemail=buf.at(5);
                        //                    char *email;//邮箱
                        //                    email=uemail.toLatin1().data();
                        //                    QString uwage=buf.at(6);
                        //                    int wage=uwage.toInt();//薪酬
                        //                    QString ugender=buf.at(7);//
                        //                    int gender=ugender.toInt();//性别
                        //                    QString apart_number=buf.at(8);
                        //                    int apart_num=apart_number.toInt();//住宿号
                        //                    QString depart=buf.at(9);
                        //                    char *department;//部门
                        //                    department=depart.toLatin1().data();
                        //                    /************删除信息*************/
                        //                    QString delete_info = QString("delete from users where EmployerID='%1'and Name='%2'and Psswd='%3' and Phone='%4' and Sign='%5' and Email='%6' and Wage='%7' and gender='%8' and Apart_num='%9' and Department='%10'").arg(Userid).arg(name).arg(password).arg(phone).arg(sign).arg(email).arg(wage).arg(gender).arg(apart_num).arg(department);
                        //                    query.exec(delete_info);
                        //                    qDebug()<<"已删除信息";
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(delete_info);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    db.close();
                        //                }
                        //                if(list.at(2)=="015")//上传任务，功能包编号
                        //                {
                        //                    QStringList buf;
                        //                    buf<<"2024"<<"shoot"<<"2021-05-18 19:58:56"<<"play football"<<"0";
                        //                    qDebug()<<"成功连接数据库";
                        //                    /************接收任务信息*************/
                        //                    QString wid=buf.at(0);
                        //                    int workid=wid.toInt();//任务id
                        //                    QString wtarget=buf.at(1);
                        //                    char *target;//任务目标
                        //                    target=wtarget.toLatin1().data();
                        //                    QString ftime=buf.at(2);
                        //                    //QDateTime found_time;//任务时间
                        //                    //found_time=QDateTime::fromString(ftime,"yyyy-MM-dd hh:mm:ss");
                        //                    QString wcontent=buf.at(3);
                        //                    char*content;
                        //                    content=wcontent.toLatin1().data();//任务内容
                        //                    QString wstatus=buf.at(4);
                        //                    int status=wstatus.toInt();//任务状态(是否完成)

                        //                    /************判断是插入还是更新*************/
                        //                    QString judge=QString("select Wid from assignment");
                        //                    query.exec(judge);//如果是数据表中已有Wid的记录，则把原有Wid的任务内容替换成新任务，反之则直接用新Wid添加新任务
                        //                    QList<qint32> wid_list;
                        //                    while (query.next())
                        //                    {
                        //                        wid_list.push_back(query.value(0).toInt());//遍历所有的wid
                        //                    }
                        //                    int temp=0;//用于判断是否有相同id
                        //                    for(int i=0;i<wid_list.size();i++)
                        //                    {
                        //                        qDebug()<<"已有的wid有:"<<wid_list.at(i);//控制台输出已有的wid
                        //                        if(workid==wid_list.at(i))//说明已有此人信息，则进行更新而不是插入
                        //                        {
                        //                            /************更新任务信息*************/
                        //                            QString update_info=QString("update assignment set Target='%2',Wtime='%3',Content='%4',Status='%5' where Wid='%1'").arg(workid).arg(target).arg(ftime).arg(content).arg(status);
                        //                            bool flag = query.exec(update_info);
                        //                            if(flag)
                        //                            {
                        //                                qDebug()<<"已更新为新任务";
                        //                            }
                        //                            /************创建事务*************/
                        //                            db.transaction();
                        //                            bool flag1 = query.exec(update_info);
                        //                            if (flag1)
                        //                            {
                        //                                db.commit();
                        //                            }
                        //                            else
                        //                            {
                        //                                db.rollback();
                        //                            }
                        //                            temp=workid;
                        //                            db.close();
                        //                            break;
                        //                        }
                        //                    }
                        //                    if(temp==0)//说明没更新
                        //                    {
                        //                        /************添加新任务*************/
                        //                        QString add_work = QString("insert into assignment(Wid,Target,Wtime,Content,Status) values('%1','%2','%3','%4','%5')").arg(workid).arg(target).arg(ftime).arg(content).arg(status);
                        //                        query.exec(add_work);
                        //                        qDebug()<<"已添加任务";
                        //                        /************创建事务*************/
                        //                        db.transaction();
                        //                        bool flag1 = query.exec(add_work);
                        //                        if (flag1)
                        //                        {
                        //                            db.commit();
                        //                        }
                        //                        else
                        //                        {
                        //                            db.rollback();
                        //                        }
                        //                        db.close();
                        //                    }
                        //                }
                        //                if(list.at(2)=="016")//所有任务列表，功能包编号
                        //                {

                        //                    /************查看任务信息*************/
                        //                    QString count_work = "select * from assignment";
                        //                    query.exec(count_work);
                        //                    query.next();
                        //                    qDebug()<<"任务列表如下:";
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(count_work);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    /************封装任务信息*************/
                        //                    QStringList work_list;//存储任务信息
                        //                    while (query.next())
                        //                    {
                        //                        for(int i=0;i<5;i++)
                        //                        {
                        //                            work_list.push_back(query.value(i).toString());
                        //                            qDebug()<<query.value(i).toString();
                        //                        }
                        //                        qDebug()<<"---------------------";
                        //                    }
                        //                    db.close();
                        //                }
                        //                if(list.at(2)=="017")//已完成任务，功能包编号
                        //                {
                        //                    /************查看已完成任务*************/
                        //                    QString check_finished_work = ("select * from assignment where Status=1");
                        //                    query.exec(check_finished_work);
                        //                    query.next();
                        //                    qDebug()<<"已完成的任务信息如下:";
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(check_finished_work);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    /************封装任务信息*************/
                        //                    QStringList finished_work_list;//创建list容器保存任务信息
                        //                    while (query.next())
                        //                    {
                        //                        for(int i=0;i<5;i++)
                        //                        {
                        //                            finished_work_list.push_back(query.value(i).toString());
                        //                            qDebug()<<query.value(i).toString();
                        //                        }
                        //                        qDebug()<<"---------------------";
                        //                    }
                        //                    db.close();
                        //                }
                        //                if(list.at(2)=="018")//未完成任务，功能包编号
                        //                {
                        //                    /************查看未完成任务*************/
                        //                    QString check_unfinished_work = ("select * from assignment where Status=0");
                        //                    query.exec(check_unfinished_work);
                        //                    query.next();
                        //                    qDebug()<<"未完成的任务信息如下:";
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(check_unfinished_work);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    /************封装任务信息*************/
                        //                    QStringList unfinished_work_list;//创建list容器保存任务信息
                        //                    while (query.next())
                        //                    {
                        //                        for(int i=0;i<5;i++)
                        //                        {
                        //                            unfinished_work_list.push_back(query.value(i).toString());
                        //                            qDebug()<<query.value(i).toString();
                        //                        }
                        //                        qDebug()<<"---------------------";
                        //                    }
                        //                    db.close();
                        //                }
                        //                if(list.at(2)=="019")//删除任务，功能包编号
                        //                {
                        //                    QStringList buf;
                        //                    buf<<"2024"<<"shoot"<<"2021-05-18 19:58:56"<<"2"<<"1";
                        //                    qDebug()<<"已收到要删除的任务id";
                        //                    /************接收任务信息*************/
                        //                    QString wid=buf.at(0);
                        //                    int workid=wid.toInt();//任务id
                        //                    QString wtarget=buf.at(1);
                        //                    char *target;//任务目标
                        //                    target=wtarget.toLatin1().data();
                        //                    QString ftime=buf.at(2);//任务时间
                        //                    QString wcontent=buf.at(3);
                        //                    char*content;
                        //                    content=wcontent.toLatin1().data();//任务内容
                        //                    QString wstatus=buf.at(4);
                        //                    int status=wstatus.toInt();//任务状态(是否完成)

                        //                    /************展示要删除的任务*************/
                        //                    QString show_work = QString("select from assignment where Wid='%1'").arg(workid);
                        //                    query.exec(show_work);
                        //                    query.next();
                        //                    qDebug()<<"要删除的任务信息如下";
                        //                    for(int i=0;i<5;i++)
                        //                    {
                        //                        qDebug()<<query.value(i).toString();
                        //                    }
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(show_work);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }

                        //                    /************删除任务*************/
                        //                    QString delete_work = QString("delete from assignment where Wid='%1'").arg(workid); //and Target='%2' and Wtime='f_time' and Content='%3' and Status='%4'").arg(workid).arg(target).arg(content).arg(status);
                        //                    query.exec(delete_work);
                        //                    qDebug()<<"已删除任务";
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag2 = query.exec(delete_work);
                        //                    if (flag2)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    db.close();
                        //                }
                        //            }
                        //            if(list.at(0)=="001")//特征码，说明是client端是员工,则下面是管理员的功能实现
                        //            {
                        //                //
                        //                if(list.at(2)=="001")//用户登录，功能包编号
                        //                {
                        //                    qDebug()<<"准备登录";
                        //                    QStringList buf;
                        //                    buf<<"1003"<<"happyday";
                        //                    qDebug()<<"已输入身份信息";

                        //                    /************接收个人信息*************/
                        //                    QString EmployerID=buf.at(0);
                        //                    int Userid=EmployerID.toInt();//员工id
                        //                    QString pwd=buf.at(1);//密码
                        //                    /************检查密码和账号是否匹配*************/
                        //                    QString check_login=QString("select EmployerID from users where EmployerID='%1'").arg(Userid);
                        //                    query.exec(check_login);
                        //                    /************展示账号和密码为*************/
                        //                    query.next();
                        //                    qDebug()<<"输入的账号为:"<<Userid<<"密码为:"<<pwd;
                        //                    qDebug()<<"正确的账号为"<<query.value(0)<<"密码为:"<<query.value(1);
                        //                    /************接收个人信息*************/
                        //                    if(query.value(1)==pwd)
                        //                    {
                        //                        qDebug()<<"密码正确:";
                        //                        //实现登录功能
                        //                    }
                        //                    else
                        //                    {
                        //                        qDebug()<<"密码错误";
                        //                        //实现拒绝登录的功能
                        //                    }
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(check_login);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    db.close();
                        //                }
                        //                if(list.at(2)=="002")//待遇查询，功能包编号
                        //                {
                        //                    qDebug()<<"准备查询待遇";
                        //                    QStringList buf;
                        //                    buf<<"1004"<<"liujc";
                        //                    qDebug()<<"已输入EmployerID和姓名";

                        //                    /************接收EmployerID和姓名信息*************/
                        //                    QString EmployerID=buf.at(0);
                        //                    int Userid=EmployerID.toInt();//员工id
                        //                    QString name=buf.at(1);//员工姓名
                        //                    /************查找待遇*************/
                        //                    QString check_wage=QString("select Wage from users where EmployerID='%1' and Name='%2'").arg(Userid).arg(name);
                        //                    query.exec(check_wage);
                        //                    query.next();
                        //                    int user_wage=query.value(0).toInt();//保存待遇值;//存储待遇信息
                        //                    qDebug()<<"工资为"<<user_wage<<"元";

                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(check_wage);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    db.close();
                        //                }
                        //                if(list.at(2)=="003")//个人信息操作，功能包编号
                        //                {


                        //                }
                        //                if(list.at(2)=="004")//查询任务，功能包编号
                        //                {
                        //                    qDebug()<<"准备查询任务";
                        //                    QStringList buf;
                        //                    buf<<"2020";
                        //                    qDebug()<<"已输入任务id";
                        //                    /************接收任务id信息*************/
                        //                    QString wid=buf.at(0);
                        //                    int workid=wid.toInt();//任务id
                        //                    /************查询任务*************/
                        //                    QString check_work = QString("select * from assignment where Wid='%1'").arg(workid);
                        //                    query.exec(check_work);
                        //                    qDebug()<<"所查询的任务信息为";
                        //                    /************展示并封装任务信息*************/
                        //                    query.next();
                        //                    QStringList work_list;//创建list容器保存任务信息
                        //                    for(int i=0;i<5;i++)
                        //                    {
                        //                        qDebug()<<query.value(i).toString();
                        //                        work_list.push_back(query.value(i).toString());
                        //                    }
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(check_work);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    db.close();
                        //                }
                        //                if(list.at(2)=="005")//上传任务进度，功能包编号
                        //                {
                        //                    qDebug()<<"准备上传任务进度";
                        //                    QStringList buf;
                        //                    buf<<"2018"<<"2";
                        //                    qDebug()<<"已输入任务号和进度";
                        //                    /************接收任务进度信息*************/
                        //                    QString wid=buf.at(0);
                        //                    int workid=wid.toInt();//任务号
                        //                    QString wstatus=buf.at(1);
                        //                    int status=wstatus.toInt();//任务进度
                        //                    /************更新任务进度状态*************/
                        //                    QString update_work = QString("update assignment set Status='%1' where Wid='%2'").arg(status).arg(workid);
                        //                    query.exec(update_work);
                        //                    qDebug()<<"所更新进度的任务信息为";
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(update_work);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    /************展示并封装任务信息*************/
                        //                    QString show= QString("select * from assignment where Wid='%1'").arg(workid);
                        //                    query.exec(show);
                        //                    query.next();
                        //                    QStringList work_list;//创建list容器保存任务信息
                        //                    for(int i=0;i<5;i++)
                        //                    {
                        //                        qDebug()<<query.value(i).toString();
                        //                        work_list.push_back(query.value(i).toString());
                        //                    }
                        //                    db.close();
                        //                }
                        //                if(list.at(2)=="006")//签到，功能包编号
                        //                {
                        //                    qDebug()<<"准备签到";
                        //                    QStringList buf;
                        //                    buf<<"1005"<<"mary"<<"1"<<"2021-05-18 19:57:56";
                        //                    qDebug()<<"已签到";
                        //                    /************接收签到的用户信息*************/
                        //                    QString EmployerID=buf.at(0);
                        //                    int userid=EmployerID.toInt();//用户id
                        //                    QString uname=buf.at(1);
                        //                    char *name;//用户姓名
                        //                    name=uname.toLatin1().data();
                        //                    QString cstatus=buf.at(2);
                        //                    int status=cstatus.toInt();//签到状态(是否签到)
                        //                    QString ctime=buf.at(3);//签到时间
                        //                    /************签到*************/
                        //                    QString clock_in = QString("update clock_in set Status='%1',Clock_in_time='%2'").arg(status).arg(ctime);
                        //                    query.exec(clock_in);
                        //                    qDebug()<<"签到人信息如下:";
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(clock_in);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    /************展示并封装任务信息*************/
                        //                    QString show= QString("select * from clock_in where EmployerID='%1'").arg(userid);
                        //                    query.exec(show);
                        //                    query.next();
                        //                    QStringList clock_in_info;//创建list容器保存任务信息
                        //                    for(int i=0;i<4;i++)
                        //                    {
                        //                        qDebug()<<query.value(i).toString();
                        //                        clock_in_info.push_back(query.value(i).toString());
                        //                    }
                        //                    db.close();
                        //                }
                        //                if(list.at(2)=="007")//员工下载文件(访问文件列表)，功能包编号
                        //                {
                        //                    QStringList buf;
                        //                    qDebug()<<"文件列表的信息如下:";
                        //                    /************查询文件信息*************/
                        //                    QString check_file_list=("select * from File");
                        //                    query.exec(check_file_list);
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(check_file_list);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    /************封装文件信息*************/
                        //                    query.next();
                        //                    QStringList file_info_list;//创建list容器保存任务信息
                        //                    while (query.next())
                        //                    {
                        //                        for(int i=0;i<8;i++)
                        //                        {
                        //                            file_info_list.push_back(query.value(i).toString());
                        //                            qDebug()<<query.value(i).toString();
                        //                        }
                        //                    }
                        //                    db.close();
                        //                }
                        //                if(list.at(2)=="008")//员工下载某一个文件，功能包编号
                        //                {
                        //                    qDebug()<<"准备选择文件";
                        //                    QStringList buf;
                        //                    buf<<"2020";
                        //                    qDebug()<<"已输入文件id";
                        //                    /************接收文件信息*************/
                        //                    QString fid=buf.at(0);
                        //                    int fileid=fid.toInt();//文件id
                        //                    /************找到对应文件的保存路径*************/
                        //                    QString find_file=QString("select Fpath from File where Fid='%1'").arg(fileid);
                        //                    query.exec(find_file);
                        //                    query.next();
                        //                    QString file_path=query.value(0).toString();//得到所选择的文件的保存路径
                        //                    /************根据路径找到文件并进行封装*************/
                        //                    QFile file(file_path);
                        //                    QFileInfo info(file_path);
                        //                    int file_size=info.size();//文件的总大小
                        //                    file.open(QFile::ReadOnly);//文件的打开方式设为只读
                        //                    while (!file.atEnd())
                        //                    {
                        //                        static int num=0;
                        //                        if(num==0)
                        //                        {
                        //                            my_socket1->write((char*)&file_size, 4);//如果是第一次循环就先把文件大小发送出去
                        //                        }
                        //                        QByteArray line = file.readLine();//如果文件没读完就一行一行的往后读
                        //                        num+=line.size();//没发送一次数据就更新一次数据大小
                        //                        //int percent=(num*100/file_size);//记录文件下载的进度
                        //                        my_socket1->write(line);//把这行数据通过套接字发送给服务器
                        //                    }
                        //                }
                        //                if(list.at(2)=="009")//员工上传文件(请求存储位置)，功能包编号
                        //                {
                        //                    qDebug()<<"准备获取文件存储位置";
                        //                    QStringList buf;
                        //                    buf<<"E:\\test1.txt";
                        //                    qDebug()<<"已输入文件存储位置信息";
                        //                    /************接收文件信息*************/
                        //                    QString file_path=buf.at(0);//文件保存路径
                        //                    emit send_path(file_path);//将路径通过信号发送给主线程
                        //                }
                        //                if(list.at(2)=="010")//员工上传文件本体，功能包编号
                        //                {
                        //                    emit get_path();//子线程向主线程发送信号申请获取文件存储位置信息
                        //                    /************接收新文件的信息*************/
                        //                    QStringList buf;
                        //                    buf<<"1001"<<"s"<<"ne"<<"liujc"<<"2022-05-02 18:00:00"<<"job";
                        //                    QString fid=buf.at(0);
                        //                    int fileid=fid.toInt();//文件id
                        //                    QString flevel=buf.at(1);
                        //                    int level=flevel.toInt();//文件等级
                        //                    QString depart=buf.at(2);//部门
                        //                    QString founder=buf.at(3);//创建人
                        //                    QString found_time=buf.at(4);//创建时间
                        //                    QString content=buf.at(5);//内容
                        //                    QDateTime file_EXtime=QDateTime::currentDateTime();//修改时间
                        //                    QString EXtime=file_EXtime.toString("yyyy-MM-dd hh:mm:ss");
                        //                    QString save_path=fpath;//文件路径
                        //                    /************将新文件的信息存入数据库*************/
                        //                    QString insert_file_info=QString("insert into file(Fid,Level,Department,Founder,Ftime,Fcontent,EXtime,Fpath) values('%1','%2','%3','%4','%5','%6','%7','%8')").arg(fileid).arg(level).arg(depart).arg(founder).arg(found_time).arg(content).arg(EXtime).arg(save_path);
                        //                    query.exec(insert_file_info);
                        //                    qDebug()<<"已更新文件信息";
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(insert_file_info);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    db.close();
                        //                    /************读取文件信息*************/
                        //                    QFile* file = new QFile(fpath);//fpath通过path函数得到主线程通过信号传过来的文件存储路径
                        //                    file->open(QFile::WriteOnly);
                        //                    static int count = 0;//统计文件接收了多少
                        //                    static int total = 0;//在第一次循环时获取文件大小信息
                        //                    if(count == 0)
                        //                    {
                        //                        my_socket1->read((char*)&total, 4);
                        //                    }
                        //                    // 读出剩余的数据
                        //                    QByteArray all = my_socket1->readAll();
                        //                    count += all.size();
                        //                    file->write(all);
                        //                    /************判断数据是否接收完了*************/
                        //                    if(count == total)
                        //                    {
                        //                        qDebug()<<"文件信息已经接收完成";
                        //                        my_socket1->close();
                        //                        my_socket1->deleteLater();
                        //                        file->close();
                        //                        file->deleteLater();
                        //                        emit over();
                        //                    }
                        //                }
                        //                if(list.at(2)=="011")//个人信息访问，功能包编号
                        //                {
                        //                    QStringList buf;
                        //                    buf<<"1004"<<"liujc";
                        //                    qDebug()<<"准备根据工号和姓名查看个人信息";
                        //                    /************接收工号和姓名信息*************/
                        //                    QString EmployerID=buf.at(0);
                        //                    int Userid=EmployerID.toInt();//员工id
                        //                    QString name=buf.at(1);
                        //                    QString check_personal_info=QString("select * from users where EmployerID='%1' and Name='%2'").arg(Userid).arg(name);
                        //                    query.exec(check_personal_info);
                        //                    /************创建事务*************/
                        //                    db.transaction();
                        //                    bool flag1 = query.exec(check_personal_info);
                        //                    if (flag1)
                        //                    {
                        //                        db.commit();
                        //                    }
                        //                    else
                        //                    {
                        //                        db.rollback();
                        //                    }
                        //                    /************封装任务信息*************/
                        //                    QString show = QString("select * from users where EmployerID='%1'").arg(Userid);
                        //                    query.exec(show);
                        //                    query.next();
                        //                    QStringList user_info_list;//创建list容器保存任务信息
                        //                    for(int i=0;i<10;i++)
                        //                    {
                        //                        user_info_list.push_back(query.value(i).toString());
                        //                        qDebug()<<query.value(i).toString();
                        //                    }
                        //                    db.close();
                        //                }
                        //                if(list.at(2)=="012")//个人信息修改，功能包编号
                        //                {
                        //                    qDebug()<<"准备写入数据库";
                        //                    QStringList buf;
                        //                    buf<<"1005"<<"mary"<<"esp2009"<<"20220630"<<"1"<<"102938476@qq.com"<<"12000"<<"1"<<"405"<<"ra";

                        //                    /************接收个人信息*************/
                        //                    QString EmployerID=buf.at(0);
                        //                    int Userid=EmployerID.toInt();//员工id
                        //                    QString uname=buf.at(1);
                        //                    char *name;
                        //                    name=uname.toLatin1().data();//姓名
                        //                    QString pwd=buf.at(2);
                        //                    char*password;
                        //                    password=pwd.toLatin1().data();//密码
                        //                    QString phone=buf.at(3);//电话
                        //                    QString usign=buf.at(4);
                        //                    int sign = usign.toInt();//权限
                        //                    QString uemail=buf.at(5);
                        //                    char *email;//邮箱
                        //                    email=uemail.toLatin1().data();
                        //                    QString uwage=buf.at(6);
                        //                    int wage=uwage.toInt();//薪酬
                        //                    QString ugender=buf.at(7);//
                        //                    int gender=ugender.toInt();//性别
                        //                    QString apart_number=buf.at(8);
                        //                    int apart_num=apart_number.toInt();//住宿号
                        //                    QString depart=buf.at(9);
                        //                    char *department;//部门
                        //                    department=depart.toLatin1().data();
                        //                    /************判断是插入还是更新*************/
                        //                    QString judge=QString("select EmployerID from users");
                        //                    query.exec(judge);//如果是数据表中已有EmployerID的记录，则进行更新，反之则插入
                        //                    QList<qint32> user_id_list;
                        //                    while (query.next())
                        //                    {
                        //                        user_id_list.push_back(query.value(0).toInt());//遍历所有的EmployerID
                        //                    }
                        //                    int temp=0;//用于判断是否有相同id
                        //                    for(int i=0;i<user_id_list.size();i++)
                        //                    {
                        //                        qDebug()<<"已有的EmployerID有:"<<user_id_list.at(i);//控制台输出已有的EmployerID
                        //                        if(Userid==user_id_list.at(i))//说明已有此人信息，则进行更新而不是插入
                        //                        {
                        //                            /************更新个人信息*************/
                        //                            QString update_info=QString("update users set Name='%2',Psswd='%3',Phone='%4',Sign='%5',Email='%6',Wage='%7',gender='%8',Apart_num='%9',Department='%10' where EmployerID='%1'").arg(Userid).arg(name).arg(password).arg(phone).arg(sign).arg(email).arg(wage).arg(gender).arg(apart_num).arg(department);
                        //                            query.exec(update_info);
                        //                            bool flag = query.exec(update_info);
                        //                            if(flag)
                        //                            {
                        //                                qDebug()<<"已更新";
                        //                            }
                        //                            /************创建事务*************/
                        //                            db.transaction();
                        //                            bool flag1 = query.exec(update_info);
                        //                            if (flag1)
                        //                            {
                        //                                db.commit();
                        //                            }
                        //                            else
                        //                            {
                        //                                db.rollback();
                        //                            }
                        //                            temp=Userid;
                        //                            db.close();
                        //                            break;
                        //                        }
                        //                    }
                        //                    if(temp==0)//说明没更新
                        //                    {
                        //                        /************插入个人信息*************/
                        //                        QString insert_info = QString("insert into users(EmployerID,Name,Psswd,Phone,Sign,Email,Wage,gender,Apart_num,Department) values('%1','%2','%3','%4','%5','%6','%7','%8','%9','%10')").arg(Userid).arg(name).arg(password).arg(phone).arg(sign).arg(email).arg(wage).arg(gender).arg(apart_num).arg(department);
                        //                        query.exec(insert_info);
                        //                        qDebug()<<"已插入";
                        //                        /************创建事务*************/
                        //                        db.transaction();
                        //                        bool flag1 = query.exec(insert_info);
                        //                        if (flag1)
                        //                        {
                        //                            db.commit();
                        //                        }
                        //                        else
                        //                        {
                        //                            db.rollback();
                        //                        }
                        //                        db.close();
                        //                    }
                        //                }
                        //            }
                        //        }
 //                   }});
                    /*如果服务结束就调用下面的代码关闭套接字服务
    my_socket1->close();
    my_socket1->deleteLater();
    emit over();*/
//                    exec();//事件循环
//               }
//    });}


