package com.macro.mall.tiny.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * 定时任务配置
 * SpringTask的配置
 * 只需要在配置类中添加一个@EnableScheduling注解即可开启SpringTask的定时任务能力
 *
 * SpringTask是Spring自主研发的轻量级定时任务工具，相比于Quartz更加简单方便，且不需要引入其他依赖即可使用。
 */
@Configuration
@EnableScheduling
public class SpringTaskConfig {
}