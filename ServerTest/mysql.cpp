#include "mysql.h"
#include <QSqlDatabase>
#include <QMessageBox>

MySQL::MySQL(QWidget *parent) : QMainWindow(parent)
{
    database = QSqlDatabase::addDatabase("QMYSQL");
    database.setHostName("localhost");//写自己的数据库
    database.setPort(3306);
    database.setDatabaseName("su");
    database.setUserName("root");
    database.setPassword("thelastofus123");
    bool ok = database.open();
    if(ok){
          qDebug()<<"成功连接数据库";
    }
    else{
          QMessageBox::warning(NULL,"警告","无法连接数据库");
    }
}
