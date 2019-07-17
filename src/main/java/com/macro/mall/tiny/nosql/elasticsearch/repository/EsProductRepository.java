package com.macro.mall.tiny.nosql.elasticsearch.repository;

import com.macro.mall.tiny.nosql.elasticsearch.document.EsProduct;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;

/**
 * 商品ES操作类
 *
 * 继承ElasticsearchRepository接口
 * 这样就拥有了一些基本的Elasticsearch数据操作方法，同时定义了一个衍生查询方法 findByNameOrSubTitleOrKeywords
 *
 * TODO: 此处为何会注入到spring ioc中？？？
 *
 * 写一个类继承ElasticsearchRepository<T, ID>，需要写两个泛型：
 *  1. 第一个代表要存储的实体类型
 *  2. 第二个代表主键类型
 */
public interface EsProductRepository extends ElasticsearchRepository<EsProduct, Long> {
    /**
     * 搜索查询
     *
     * @param name              商品名称
     * @param subTitle          商品标题
     * @param keywords          商品关键字
     * @param page              分页信息
     * @return
     */
    Page<EsProduct> findByNameOrSubTitleOrKeywords(String name, String subTitle, String keywords, Pageable page);
}