package com.macro.mall.tiny.service;

import com.macro.mall.tiny.mbg.model.UmsAdmin;
import com.macro.mall.tiny.mbg.model.UmsPermission;

import java.util.List;

public interface UmsAdminService {
    UmsAdmin getAdminByUsername(String username);

    UmsAdmin register(UmsAdmin umsAdminParam);

    String login(String username, String password);

    List<UmsPermission> getPermissionList(Long adminId);
}
