#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTcpServer>
#include <QTcpSocket>
#include <QSqlDatabase>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    QTcpServer* my_server=new QTcpServer(this);//创建服务器对象
    int login_auth;//用户登录类型(管理员or普通员工)
    QString uid;//用户登录id
    QString file_save_path="E:/test1.txt";//保存员工所选择的文件存储路径

private:
    Ui::MainWindow *ui;

signals:
    void login_auth_info(int);//将用户登录类型发送给子线程
    void uid_info(QString);//将用户id信息发送给子线程
    void file_path_info(QString);//将员工所选择的文件存储路径发送给子线程

};

#endif // MAINWINDOW_H
