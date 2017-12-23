/******************************************************************************
*
* Copyright (C) Chaoyong Zhou
* Email: bgnvendor@163.com
* QQ: 2796796
*
*******************************************************************************/
#ifdef __cplusplus
extern "C"{
#endif/*__cplusplus*/

#include "db_internal.h"

uint8_t btreeSplit(const BTree *src_tree, const RawFile *src_rawFile,
                    BTree *des_tree_left, RawFile *des_rawFile_left,
                    BTree *des_tree_right, RawFile *des_rawFile_right)
{
    BTreeTraversal *trav;
    uint32_t count;
    offset_t offset;

    if (src_tree == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeSplit: src tree is null\n");
        return 0;/*fail*/
    }
    trav = btreeInitTraversal(src_tree);

    for(count = 0, offset = btreeGetFirstOffset(trav);
        count < (src_tree->size / 2) && 0 != offset;
        count ++, offset = btreeGetNextOffset(trav))
    {
        uint32_t data_len;
        uint32_t kv_len;
        uint8_t *kv;
        uint8_t *key;
        uint32_t filePos;

        if(RAW_FILE_FAIL == rawFileRead32(src_rawFile, &data_len, offset))
        {
            dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT,"error:btreeSplit: read data_len at offset %d failed where count reaches %d\n", offset, count);
            btreeDestroyTraversal(trav);
            return 0;
        }

        kv = (uint8_t *)SAFE_MALLOC(data_len, LOC_BTREE_0026);
        if(NULL == kv)
        {
            dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeSplit: alloc %d bytes failed\n", data_len);
            return 0;
        }

        if(RAW_FILE_FAIL == rawFileRead8s(src_rawFile, kv, data_len, &kv_len, offset + sizeof(uint32_t)) || kv_len != data_len)
        {
            dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT,"error:btreeSplit: read kv %ld bytes at offset %d failed where count reaches %d, kv_len = %d\n",
                    data_len, offset + sizeof(uint32_t), count, kv_len);

            SAFE_FREE(kv, LOC_BTREE_0027);
            btreeDestroyTraversal(trav);
            return 0;
        }

        //dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT, "[DEBUG] btreeSplit: read kv[1]: ");
        //kvPrintHs(LOGSTDOUT, kv);

        key = kv;

        rawFileAppend8slen(des_rawFile_left, kv, kv_len, &filePos);
        btreeInsert(des_tree_left, key, filePos, 0);

        SAFE_FREE(kv, LOC_BTREE_0028);
    }

    for(;
        count < src_tree->size && 0 != offset;
        count ++, offset = btreeGetNextOffset(trav))
    {
        uint32_t data_len;
        uint32_t kv_len;
        uint8_t *kv;
        uint8_t *key;
        uint32_t filePos;

        if(RAW_FILE_FAIL == rawFileRead32(src_rawFile, &data_len, offset))
        {
            dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT,"error:btreeSplit: read data_len at offset %d failed where count reaches %d\n", offset, count);
            btreeDestroyTraversal(trav);
            return 0;
        }

        kv = (uint8_t *)SAFE_MALLOC(data_len, LOC_BTREE_0029);
        if(NULL == kv)
        {
            dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeSplit: alloc %d bytes failed\n", data_len);
            return 0;
        }

        if(RAW_FILE_FAIL == rawFileRead8s(src_rawFile, kv, data_len, &kv_len, offset + sizeof(uint32_t)) || kv_len != data_len)
        {
            dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT,"error:btreeSplit: read kv %ld bytes at offset %d failed where count reaches %d, kv_len = %d\n",
                    data_len, offset + sizeof(uint32_t), count, kv_len);

            SAFE_FREE(kv, LOC_BTREE_0030);
            btreeDestroyTraversal(trav);
            return 0;
        }

        //dbg_log(SEC_0130_BTREE, 9)(LOGSTDOUT, "[DEBUG] btreeSplit: read kv[2]: ");
        //kvPrintHs(LOGSTDOUT, kv);

        key = kv;

        rawFileAppend8slen(des_rawFile_right, kv, kv_len, &filePos);
        btreeInsert(des_tree_right, key, filePos, 0);

        SAFE_FREE(kv, LOC_BTREE_0031);
    }

    btreeDestroyTraversal(trav);
    return 1;
}

uint8_t btreeCompact(const BTree *src_tree, const RawFile *src_rawFile,
                    BTree *des_tree, RawFile *des_rawFile)
{
    BTreeTraversal *trav;
    offset_t offset;

    if (src_tree == NULL)
    {
        dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT, "error:btreeCompact: src tree is null\n");
        return 0;/*fail*/
    }
    trav = btreeInitTraversal(src_tree);

    for(offset = btreeGetFirstOffset(trav);
        0 != offset;
        offset = btreeGetNextOffset(trav))
    {
        uint32_t data_len;
        uint32_t kv_len;
        uint8_t *kv;
        uint8_t *key;
        uint32_t filePos;

        if(RAW_FILE_FAIL == rawFileRead32(src_rawFile, &data_len, offset))
        {
            dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT,"error:btreeCompact: read data_len at offset %d failed\n", offset);
            btreeDestroyTraversal(trav);
            return 0;
        }

        MEM_CHECK(kv = (uint8_t *)SAFE_MALLOC(data_len, LOC_BTREE_0032));

        if(RAW_FILE_FAIL == rawFileRead8slen(src_rawFile, kv, data_len, &kv_len, offset) || kv_len != data_len)
        {
            dbg_log(SEC_0130_BTREE, 0)(LOGSTDOUT,"error:btreeCompact: read kv %ld bytes at offset %d failed where kv_len = %d\n",
                    data_len, offset, kv_len);

            SAFE_FREE(kv, LOC_BTREE_0033);
            btreeDestroyTraversal(trav);
            return 0;
        }

        key = kv;

        rawFileAppend8slen(des_rawFile, kv, kv_len, &filePos);
        btreeInsert(des_tree, key, filePos, 0);

        SAFE_FREE(kv, LOC_BTREE_0034);
    }

    btreeDestroyTraversal(trav);
    return 1;
}

#ifdef __cplusplus
}
#endif/*__cplusplus*/


