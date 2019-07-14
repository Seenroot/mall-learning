package com.macro.mall.tiny.service;

import com.macro.mall.tiny.common.api.CommonResult;
import com.macro.mall.tiny.dto.OrderParam;

public interface OmsPortalOrderService {
    CommonResult generateOrder(OrderParam orderParam);

    void cancelOrder(Long orderId);
}
