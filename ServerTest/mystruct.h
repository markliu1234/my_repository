#ifndef MYSTRUCT_H
#define MYSTRUCT_H
#include <QString>
#include<QTime>
#include<QDebug>


using namespace std;


//创建并写入文本
void writeCiphertext(string ciphertext, string fileName);

//读入文本
string getText(string filename);

void md5(string keyword);

class Certificate
  {
public:
    QString version;//版本号
    QString serial;//序列号
    QString deadline;//有效日期
    QString name;//主体名
    QString pk;//公钥
  };

class FunctionBox
{

public:

    QString Group_feature_code;
    QString Packet_type;
    QString Function_pack_type;
    QString Encoding_type;
    QString Time_stamp;
    QString Ack="0";
    QString Status_code="0";
    QString Extend="0";
    QString Sender_IP="192.168.53.112,";
    QString Receiver_IP="192.168.53.112,";
//    CLog::LogConfig logConfig;
////////////////////////////////
};

   class My_k
  {
   public:
      QString key;
  };

   class Message1
  {
      QString IDc;
      QString IDt;
      QString TS;
  };
   class Ticket
  {
      QString key;
      QString IDc;
      QString ADc;
      QString IDt;
      QString TS;
      QString Lifetime;
  };

   class Message2
  {
      QString key;
      QString IDt;
      QString TS;
      QString Lifetime;
      Ticket t;
  };

   class Authenticator
  {
      QString IDc;
      QString ADc;
      QString TS;
  };


   class Message3
  {
      QString IDv;
      Ticket t;
      Authenticator Ac;
  };

   class Message4
  {
      QString Key;
      QString IDv;
      QString TS;
      Ticket t;
  };



   class Message5
  {
      Ticket t;
      Authenticator Ac;
  };

   class Message6
  {
      QString TS;
  };

#endif // MYSTRUCT_H
