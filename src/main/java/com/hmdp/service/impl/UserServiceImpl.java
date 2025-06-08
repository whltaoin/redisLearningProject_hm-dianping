package com.hmdp.service.impl;

import cn.hutool.Hutool;
import cn.hutool.core.bean.BeanUtil;
import cn.hutool.core.lang.Snowflake;
import cn.hutool.core.lang.UUID;
import cn.hutool.core.util.RandomUtil;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.hmdp.dto.LoginFormDTO;
import com.hmdp.dto.Result;
import com.hmdp.dto.UserDTO;
import com.hmdp.entity.User;
import com.hmdp.mapper.UserMapper;
import com.hmdp.service.IUserService;
import com.hmdp.utils.RegexUtils;
import com.sun.deploy.security.WSeedGenerator;
import lombok.extern.log4j.Log4j;
import lombok.extern.slf4j.Slf4j;
import org.omg.CORBA.TIMEOUT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static com.hmdp.utils.RedisConstants.*;
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
    @Autowired
   private  StringRedisTemplate stringRedisTemplate;


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
//        // 3 存储验证码
//        session.setAttribute("code",code);
        //  3 修改为redis存储

        stringRedisTemplate.opsForValue().set(LOGIN_CODE_KEY+phone,code,LOGIN_CODE_TTL, TimeUnit.MINUTES); // 1分钟过期
        // 4 发送验证码,模拟，不调用第三方功能
        log.debug("发送短信验证码成功，验证码：{}",code);

        return Result.ok();
    }

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

    private User createUserWithPhone(String phone) {
        User user = new User();
        user.setPhone(phone);
        user.setNickName(USER_NICK_NAME_PREFIX+RandomUtil.randomString(6));
        // 保存
        save(user);
        return user;
    }
}
