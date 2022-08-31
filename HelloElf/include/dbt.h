#ifndef __DBT_H__
#define __DBT_H__

#include <stdint.h>

bool dbt_init(void* mainCacheBegin, size_t mainCacheSize);
void* dbt_enter(void* address);

#endif