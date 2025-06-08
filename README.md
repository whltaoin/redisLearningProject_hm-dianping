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

# 三、基于session实现登录功能
### 具体实现流程图
![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749347306713-3764774c-8caf-4c42-95fc-9c154ec29bd7.png)

### 实现发送验证码
1. 查询发送验证码请求API

> 地址：/user/code
>
> 请求方式：POST
>

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749348235199-3d2826ee-ca0f-410b-8efc-f4d19566f2c7.png)

2. 修改UserController中的发送验证码方法

```java
/**
     * 发送手机验证码
     */
@PostMapping("code")
public Result sendCode(@RequestParam("phone") String phone, HttpSession session) {
    //        // TODO 发送短信验证码并保存验证码
    //        return Result.fail("功能未完成");
    // 实现发送验证码
    return userService.sendCode(phone,session);
}
```

3. 在service中实现send方法

```java
package com.hmdp.service.impl;

import cn.hutool.Hutool;
import cn.hutool.core.util.RandomUtil;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.hmdp.dto.Result;
import com.hmdp.entity.User;
import com.hmdp.mapper.UserMapper;
import com.hmdp.service.IUserService;
import com.hmdp.utils.RegexUtils;
import lombok.extern.log4j.Log4j;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;



/**
 * <p>
 * 服务实现类
 * </p>
 *
 * @since 2021-12-22
 */
@Service
@Slf4j
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements IUserService {

    /**
     * 发送验证码
     * @param phone
     * @param session
     * @return
     */
    @Override
    public Result sendCode(String phone, HttpSession session) {

        // 1 验证手机号
        if (RegexUtils.isPhoneInvalid(phone)) {
            return Result.fail("手机号格式错误，请重新输入");
        }
        // 2 生成验证码
        String code = RandomUtil.randomString(6);
        // 3 存储验证码
        session.setAttribute("code",code);
        // 4 发送验证码,模拟，不调用第三方功能
        log.debug("发送短信验证码成功，验证码：{}",code);

        return Result.ok();
    }
}

```

4. 深入正确的手机号，点击发送后的效果

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749349011255-1063ed57-eb6f-4f9d-ba8e-d6126c9d4425.png)

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749349037102-f5b5e0a4-59db-41da-9215-d8f452da9d9c.png)



### 登录功能实现
1. 登录API信息

> 地址：/user/login
>
> 请求方式：POST
>

2. 在UserService中添加Login方法

```java
/**
     * 登录功能
     * @param loginForm 登录参数，包含手机号、验证码；或者手机号、密码
     */
    @PostMapping("/login")
    public Result login(@RequestBody LoginFormDTO loginForm, HttpSession session){
        // TODO 实现登录功能
//        return Result.fail("功能未完成");
        return userService.login(loginForm,session);
    }
```

3. 实现Login方法

```java
package com.hmdp.service.impl;

import cn.hutool.Hutool;
import cn.hutool.core.util.RandomUtil;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.hmdp.dto.LoginFormDTO;
import com.hmdp.dto.Result;
import com.hmdp.entity.User;
import com.hmdp.mapper.UserMapper;
import com.hmdp.service.IUserService;
import com.hmdp.utils.RegexUtils;
import com.sun.deploy.security.WSeedGenerator;
import lombok.extern.log4j.Log4j;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;

import static com.hmdp.utils.SystemConstants.USER_NICK_NAME_PREFIX;


/**
 * <p>
 * 服务实现类
 * </p>
 *
 * @since 2021-12-22
 */
@Service
@Slf4j
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements IUserService {

    

    /**
     * 登录和注册
     * @param loginForm
     * @param session
     * @return
     */

    @Override
    public Result login(LoginFormDTO loginForm, HttpSession session) {
        // 1 判断手机号
        String phone = loginForm.getPhone();
        if (RegexUtils.isPhoneInvalid(phone)) {
            return Result.fail("手机号格式错误，请重新输入");
        }
        // 2 判断验证码
        String webCode = loginForm.getCode();
        String sessionCode = session.getAttribute("code").toString();
        if (webCode==null || !webCode.equals(sessionCode)) {
            return Result.fail("验证码错误");

        }

        //
        log.debug("手机号为：{}；验证码为：{}",phone,sessionCode);

        // 3 查询用户是否存在
        User user = query().eq("phone",phone).one();
        System.out.println("-==--------------");
        System.out.println(user);
        System.out.println("-==--------------");

        // 4 不存在用户创建
        if (user==null){
            user = createUserWithPhone(phone);
            System.out.println(user);
        }
        // 5 存在用户到session中
        session.setAttribute("user",user);


        return Result.ok();
    }

    private User createUserWithPhone(String phone) {
        User user = new User();
        user.setPhone(phone);
        user.setNickName(USER_NICK_NAME_PREFIX+RandomUtil.randomString(6));
        // 保存
        save(user);
        return user;
    }
}

```

4. 实现效果

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749353161471-7a62440c-fb93-4020-8a2c-5cf1de73def7.png)

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749353192633-9af70488-9e29-46cf-85d8-7c67e9ebff53.png)

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749353239067-0530aead-447f-4a43-909a-c68128991a6e.png)

### 实现登录校验功能
1. 涉及到的controller API

> 地址：/user/me
>
> 请求方式：get
>

2. 编写登录拦截器工具类（LoginInterceptor）

```java
package com.hmdp.utils;


import com.hmdp.entity.User;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class LoginInterceptor implements HandlerInterceptor {

    /**
     * 此方法的作用是在请求进入到Controller进行拦截，有返回值
     * @param request
     * @param response
     * @param handler
     * @return
     * @throws Exception
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

        // 1 获取session
        HttpSession session = request.getSession();
        // 2 获取用户
        Object user = session.getAttribute("user");

        // 3 判断用户
        if (user==null) {
            response.setStatus(401);
            return false;
        }
        // 4  存储用户
        UserHolder.saveUser((User) user);
        // 5 放行
        return true;
    }

    /**
     * 该方法是在ModelAndView返回给前端渲染后执行
     * @param request
     * @param response
     * @param handler
     * @param ex
     * @throws Exception
     */

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
       UserHolder.removeUser();
    }
}

```

3. 添加配置MVC拦截器配置类(MvcConfig)

```java
package com.hmdp.config;


import com.hmdp.utils.LoginInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MvcConfig  implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
      registry.addInterceptor(new LoginInterceptor()
      ).excludePathPatterns(
              "/shop/**",
              "/shop-type/**",
              "/upload/**",
              "blog/hot",
              "/user/code",
              "/user/login"

      );
    }
}

```

4. 让在threadLocal存储用户返回到签到(userController)

```java

    @GetMapping("/me")
    public Result me(){
//        // TODO 获取当前登录的用户并返回
//        return Result.fail("功能未完成");
        return Result.ok(UserHolder.getUser());
    }
```

5. 运行效果
    1. 登录成功后，会跳转到用户个人主页，并显示用户的一些信息

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749364158158-a77212b4-ccb3-48ad-8710-0049b87722b6.png)	

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749363980053-87e9da46-c9a1-4d7f-87d9-649e5e51d7fd.png)

### UserDTO类使用
1. 在后端直接返回User类后，可能用用户敏感信息泄露的风险。
    1. 所以我们在存如Session时，只存储不太重要的信息即可。
2. 需要修改的地方：
    1. UserService中session存储类型

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749364708791-14755a2e-6b74-4e3b-9871-899caab661dd.png)

    2. 拦截器

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749364734018-829b4024-7f65-4bb8-afc4-300d904eeef8.png)

3. 效果

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749364844272-983ef77f-5571-4a9e-a7f7-285fc7623324.png)



### 集群Session共享存在的问题
1. 存在问题，
    1. 因为在tomcat中的Session是不共享的，如果使用了tomcat集群的话，每个tomcat中的Session都需要重新存储数据，同时可能会造成数据的不一致和数据丢失的可能。
2. 为了解决session存在问题，同时需要满足
    1. 数据共享
    2. 内存存储
    3. Key、value结构
3. 从而引入了Redis替代Session

# 四、Redis替代Session的解决方案流程图
1. 替换流程

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749381491694-4edf502e-3fec-49aa-9d39-b3e5d785b95f.png)

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749381511465-0a19133b-a9b2-438e-8be6-bc6a7cc4eac3.png)



### Redis替换Session具体实现
1. 首先将生成的验证码存入Redis中

```java
  @Override
    public Result sendCode(String phone, HttpSession session) {

        // 1 验证手机号
        if (RegexUtils.isPhoneInvalid(phone)) {
            return Result.fail("手机号格式错误，请重新输入");
        }
        // 2 生成验证码
        String code = RandomUtil.randomString(6);
//        // 3 存储验证码
//        session.setAttribute("code",code);
        //  3 修改为redis存储

        stringRedisTemplate.opsForValue().set(LOGIN_CODE_KEY+phone,code,LOGIN_CODE_TTL, TimeUnit.MINUTES); // 1分钟过期
        // 4 发送验证码,模拟，不调用第三方功能
        log.debug("发送短信验证码成功，验证码：{}",code);

        return Result.ok();
    }
```

![](https://cdn.nlark.com/yuque/0/2025/png/38516294/1749381666748-e91abb98-4947-45d9-8a69-ab022669db12.png)

2. 在用户点击登录时，从Redis中获取验证码进行判断
3. 后续将登录的用户存储到Redis中，并返回Token

```java
  @Override
    public Result login(LoginFormDTO loginForm, HttpSession session) {
        // 1 判断手机号
        String phone = loginForm.getPhone();
        if (RegexUtils.isPhoneInvalid(phone)) {
            return Result.fail("手机号格式错误，请重新输入");
        }
        // 2 判断验证码
        String webCode = loginForm.getCode();
       // String sessionCode = session.getAttribute("code").toString();
        // 从redis中获取验证码
        String sessionCode = stringRedisTemplate.opsForValue().get(LOGIN_CODE_KEY+phone);
        if (webCode==null || !webCode.equals(sessionCode)) {
            return Result.fail("验证码错误");

        }

        //
        log.debug("手机号为：{}；验证码为：{}",phone,sessionCode);

        // 3 查询用户是否存在
        User user = query().eq("phone",phone).one();
        System.out.println("-==--------------");
        System.out.println(user);
        System.out.println("-==--------------");

        // 4 不存在用户创建
        if (user==null){
            user = createUserWithPhone(phone);
            System.out.println(user);
        }
        // 5 存在用户到session中
        // 6 为了防止敏感信息泄露，将user转存到UserDTO中
        session.setAttribute("user", BeanUtil.copyProperties(user, UserDTO.class));
        UserDTO userDTO = BeanUtil.copyProperties(user, UserDTO.class);
        String token = UUID.randomUUID().toString(false);// 不带下划线的UUID

        // 将UserDTO bean转为HashMap
        Map<String, Object> userDTOMap = BeanUtil.beanToMap(userDTO);
//        System.out.println(userDTOMap);
        userDTOMap.put("id",userDTO.getId().toString()); // StringRedisTamplate 只能存String类型的数据，ID为Long，需要单独处理
        String tokenKey = LOGIN_USER_KEY+token;

        stringRedisTemplate.opsForHash().putAll(tokenKey, userDTOMap);
        stringRedisTemplate.expire(tokenKey,LOGIN_USER_TTL, TimeUnit.SECONDS);

        return Result.ok(token);
    }
```

4. 登录功能验证
    1. 用户登录完成后，在访问其他请求时，会进入到拦截器中，从请求的header中获取到Token，再通过Token查询Redis中的用户是否存在。存在就放行，并重新刷新Redis保存数据的TTL，不存在则拦截。

```java
package com.hmdp.utils;


import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.util.StrUtil;
import com.hmdp.dto.UserDTO;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.hmdp.utils.RedisConstants.LOGIN_USER_KEY;
import static com.hmdp.utils.RedisConstants.LOGIN_USER_TTL;

/**
 * 刷新Token拦截器
 */

public class RefreshTokenInterceptor implements HandlerInterceptor {
    private StringRedisTemplate stringRedisTemplate;
    public RefreshTokenInterceptor(StringRedisTemplate stringRedisTemplate ){
        this.stringRedisTemplate = stringRedisTemplate;
    }



    /**
     * 此方法的作用是在请求进入到Controller进行拦截，有返回值
     * @param request
     * @param response
     * @param handler
     * @return
     * @throws Exception
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {

//        // 1 获取session
//        HttpSession session = request.getSession();
        // 获取token
        String token = request.getHeader("authorization");
        if (StrUtil.isBlank(token)) {

            return  true;
        }
        // 2 获取用户
//        Object user = session.getAttribute("user");

        Map<Object, Object> userMap = stringRedisTemplate.opsForHash().entries(LOGIN_USER_KEY+token);


        // 3 判断用户
        if (userMap.isEmpty()) {

            return true;
        }
        UserDTO userDTO = BeanUtil.fillBeanWithMap(userMap, new UserDTO(), false);// map转bean
// 4  存储用户
        UserHolder.saveUser(userDTO);
        // 刷新token有效期
        stringRedisTemplate.expire(LOGIN_USER_KEY+token,LOGIN_USER_TTL, TimeUnit.SECONDS);
        // 5 放行
        return true;
    }

    /**
     * 该方法是在ModelAndView返回给前端渲染后执行
     * @param request
     * @param response
     * @param handler
     * @param ex
     * @throws Exception
     */

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
       UserHolder.removeUser();
    }
}

```

### 登录遗留问题解决
1. 我们之前在LoginInterceptor中有放行了一些不需要的认证的请求，这样就存在问题了。
    1. 例如：如果用户登录了，但是一直停留在不需要认证的请求上，Redis的TTL的刷新TTL功能就不会执行，导致用户被强制退出系统。
2. 解决方案：
    1. 我们在LoginInterceptor之前在设置一个全局的拦截起，并设置全局拦截，并将Login拦截器内容判断都移动到RefershToken拦截器上，在Refresh执行后再进入到Login拦截器，在判断线程中是否有登录用户，在进行实际的拦截。
3. 具体实现

LoginInterceptor

```java
package com.hmdp.utils;


import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.util.StrUtil;
import com.hmdp.dto.UserDTO;
import com.hmdp.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.hmdp.utils.RedisConstants.LOGIN_USER_KEY;
import static com.hmdp.utils.RedisConstants.LOGIN_USER_TTL;

/**
 * 登录拦截器
 */

public class LoginInterceptor implements HandlerInterceptor {




    /**
     * 此方法的作用是在请求进入到Controller进行拦截，有返回值
     * @param request
     * @param response
     * @param handler
     * @return
     * @throws Exception
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // 获取不到用户，拦截
        if (UserHolder.getUser()==null) {
            response.setStatus(401);
            return false;
        }
        return true;
    }

    /**
     * 该方法是在ModelAndView返回给前端渲染后执行
     * @param request
     * @param response
     * @param handler
     * @param ex
     * @throws Exception
     */

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
       UserHolder.removeUser();
    }
}

```

RefreshTokenInterceptor如上图

MnvConfig配置类修改如下

```java
package com.hmdp.config;


import com.hmdp.utils.LoginInterceptor;

import com.hmdp.utils.RefreshTokenInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class MvcConfig  implements WebMvcConfigurer {
    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    /**
     * order值越小，拦截顺序越高。
     * @param registry
     */
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor( new RefreshTokenInterceptor(stringRedisTemplate)).order(0);

      registry.addInterceptor(new LoginInterceptor()
      ).excludePathPatterns(
              // 放行的路径
              "/shop/**",
              "/shop-type/**",
              "/upload/**",
              "blog/hot",
              "/user/code",
              "/user/login"

      ).order(1);

    }
}

```





