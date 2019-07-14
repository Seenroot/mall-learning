package com.macro.mall.tiny.service;

import com.macro.mall.tiny.common.api.CommonResult;

public interface UmsMemberService {
    CommonResult generateAuthCode(String telephone);

    // 对输入的验证码进行校验
    CommonResult verifyAuthCode(String telephone, String authCode);
}
