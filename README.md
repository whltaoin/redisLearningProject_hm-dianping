# 一、导入黑马点评后端项目
### 项目架构图
    1. 前期阶段

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749294919318-e1047ff2-5e55-4177-8ce8-0be5af611dae.png)

    2. 后续阶段

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749295045479-5357cbfb-7489-456b-93a3-645edb9bf6b4.png)

### 导入后端项目需要注意的问题
1. 修改application.yaml文件
    1. mysql地址配置
    2. redis地址配置
2. 该项目的JDK版本为8,需要修改的地方如下图所示：
    1. idea设置

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749299001900-b11e0820-f2b7-4cda-abb7-10572b3de4e9.png)

    2. 项目结构设置

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749299073515-df0e74ee-f056-43b7-9a30-8ef09ef00741.png)

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749299087606-cb4ad13b-0e53-4edf-a544-45a2b7156c63.png)

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749299151928-357d6754-15c8-433f-9b6d-398e78361aa3.png)

### 项目启动报错
1. 报错内容：

```java
Failed to load property source from location ‘classpath:/application.yml‘
```

2. 解决方法1
    1. 查看yaml文件中的配置是否**<font style="color:#DF2A3F;">配置完整，格式正确</font>**
3. 解决方法2
    1. 设置yaml文件的文件格式为：UTF-8
    2. 设置方法为：file->setting-><font style="color:rgb(77, 77, 77);">File Encodings</font>

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749299401655-5fd83b89-115a-41f7-8a2f-eb83b5a05691.png)

### 项目启动测试
1. 喜爱过目正常启动后，访问：http://localhost:8081/shop-type/list
2. 下图为正确启动结果

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749299456011-01d845c0-0276-4063-9b9e-8d4b8f7a3852.png)

# 二、导入并启动前端项目
1. 提示：前端项目已经打包并导入到了nginx-1.18.0文件夹中的。
    1. 启动前端项目只需要执行ngin的开启命令即可。

```powershell
start nginx
```

2. 访问前端路径：http://localhost:8080

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749299824023-2e40f3e2-92cd-4424-9e5e-933e74727751.png)

