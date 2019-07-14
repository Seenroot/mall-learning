package com.macro.mall.tiny.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;

/**
 * MyBatis配置类
 */
@Configuration
// mybatis配置文件扫描 第一个是mybatis generator生成的 第二个是手动编写的（同时要在src/main/resources/mapper中手动编写mybatis 配置文件）
@MapperScan({"com.macro.mall.tiny.mbg.mapper", "com.macro.mall.tiny.dao"})
public class MyBatisConfig {
}