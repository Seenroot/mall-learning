package com.macro.mall.tiny.service;

import com.macro.mall.tiny.nosql.elasticsearch.document.EsProduct;
import org.springframework.data.domain.Page;

import java.util.List;

public interface EsProductService {
    int importAll();

    void delete(Long id);

    EsProduct create(Long id);

    void delete(List<Long> ids);

    Page<EsProduct> search(String keyword, Integer pageNum, Integer pageSize);
}
