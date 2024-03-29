#include <stdint.h>

static uint32_t crc32_context = 0xFFFFFFFFUL;
static void transparent_crc(uint64_t x, char *y, int z) {}
static void crc32_gentab() {}
static void platform_main_begin() {}
static void platform_main_end(uint32_t x, int y) {}

#define safe_add_func_int8_t_u_u
#define safe_add_func_int8_t_u_s
#define safe_add_func_int8_t_s_u
#define safe_add_func_int8_t_s_s
#define safe_add_func_uint8_t_u_u
#define safe_add_func_uint8_t_u_s
#define safe_add_func_uint8_t_s_u
#define safe_add_func_uint8_t_s_s
#define safe_add_func_int16_t_u_u
#define safe_add_func_int16_t_u_s
#define safe_add_func_int16_t_s_u
#define safe_add_func_int16_t_s_s
#define safe_add_func_uint16_t_u_u
#define safe_add_func_uint16_t_u_s
#define safe_add_func_uint16_t_s_u
#define safe_add_func_uint16_t_s_s
#define safe_add_func_int32_t_u_u
#define safe_add_func_int32_t_u_s
#define safe_add_func_int32_t_s_u
#define safe_add_func_int32_t_s_s
#define safe_add_func_uint32_t_u_u
#define safe_add_func_uint32_t_u_s
#define safe_add_func_uint32_t_s_u
#define safe_add_func_uint32_t_s_s
#define safe_add_func_int64_t_u_u
#define safe_add_func_int64_t_u_s
#define safe_add_func_int64_t_s_u
#define safe_add_func_int64_t_s_s
#define safe_add_func_uint64_t_u_u
#define safe_add_func_uint64_t_u_s
#define safe_add_func_uint64_t_s_u
#define safe_add_func_uint64_t_s_s
#define safe_sub_func_int8_t_u_u
#define safe_sub_func_int8_t_u_s
#define safe_sub_func_int8_t_s_u
#define safe_sub_func_int8_t_s_s
#define safe_sub_func_uint8_t_u_u
#define safe_sub_func_uint8_t_u_s
#define safe_sub_func_uint8_t_s_u
#define safe_sub_func_uint8_t_s_s
#define safe_sub_func_int16_t_u_u
#define safe_sub_func_int16_t_u_s
#define safe_sub_func_int16_t_s_u
#define safe_sub_func_int16_t_s_s
#define safe_sub_func_uint16_t_u_u
#define safe_sub_func_uint16_t_u_s
#define safe_sub_func_uint16_t_s_u
#define safe_sub_func_uint16_t_s_s
#define safe_sub_func_int32_t_u_u
#define safe_sub_func_int32_t_u_s
#define safe_sub_func_int32_t_s_u
#define safe_sub_func_int32_t_s_s
#define safe_sub_func_uint32_t_u_u
#define safe_sub_func_uint32_t_u_s
#define safe_sub_func_uint32_t_s_u
#define safe_sub_func_uint32_t_s_s
#define safe_sub_func_int64_t_u_u
#define safe_sub_func_int64_t_u_s
#define safe_sub_func_int64_t_s_u
#define safe_sub_func_int64_t_s_s
#define safe_sub_func_uint64_t_u_u
#define safe_sub_func_uint64_t_u_s
#define safe_sub_func_uint64_t_s_u
#define safe_sub_func_uint64_t_s_s
#define safe_mul_func_int8_t_u_u
#define safe_mul_func_int8_t_u_s
#define safe_mul_func_int8_t_s_u
#define safe_mul_func_int8_t_s_s
#define safe_mul_func_uint8_t_u_u
#define safe_mul_func_uint8_t_u_s
#define safe_mul_func_uint8_t_s_u
#define safe_mul_func_uint8_t_s_s
#define safe_mul_func_int16_t_u_u
#define safe_mul_func_int16_t_u_s
#define safe_mul_func_int16_t_s_u
#define safe_mul_func_int16_t_s_s
#define safe_mul_func_uint16_t_u_u
#define safe_mul_func_uint16_t_u_s
#define safe_mul_func_uint16_t_s_u
#define safe_mul_func_uint16_t_s_s
#define safe_mul_func_int32_t_u_u
#define safe_mul_func_int32_t_u_s
#define safe_mul_func_int32_t_s_u
#define safe_mul_func_int32_t_s_s
#define safe_mul_func_uint32_t_u_u
#define safe_mul_func_uint32_t_u_s
#define safe_mul_func_uint32_t_s_u
#define safe_mul_func_uint32_t_s_s
#define safe_mul_func_int64_t_u_u
#define safe_mul_func_int64_t_u_s
#define safe_mul_func_int64_t_s_u
#define safe_mul_func_int64_t_s_s
#define safe_mul_func_uint64_t_u_u
#define safe_mul_func_uint64_t_u_s
#define safe_mul_func_uint64_t_s_u
#define safe_mul_func_uint64_t_s_s
#define safe_div_func_int8_t_u_u
#define safe_div_func_int8_t_u_s
#define safe_div_func_int8_t_s_u
#define safe_div_func_int8_t_s_s
#define safe_div_func_uint8_t_u_u
#define safe_div_func_uint8_t_u_s
#define safe_div_func_uint8_t_s_u
#define safe_div_func_uint8_t_s_s
#define safe_div_func_int16_t_u_u
#define safe_div_func_int16_t_u_s
#define safe_div_func_int16_t_s_u
#define safe_div_func_int16_t_s_s
#define safe_div_func_uint16_t_u_u
#define safe_div_func_uint16_t_u_s
#define safe_div_func_uint16_t_s_u
#define safe_div_func_uint16_t_s_s
#define safe_div_func_int32_t_u_u
#define safe_div_func_int32_t_u_s
#define safe_div_func_int32_t_s_u
#define safe_div_func_int32_t_s_s
#define safe_div_func_uint32_t_u_u
#define safe_div_func_uint32_t_u_s
#define safe_div_func_uint32_t_s_u
#define safe_div_func_uint32_t_s_s
#define safe_div_func_int64_t_u_u
#define safe_div_func_int64_t_u_s
#define safe_div_func_int64_t_s_u
#define safe_div_func_int64_t_s_s
#define safe_div_func_uint64_t_u_u
#define safe_div_func_uint64_t_u_s
#define safe_div_func_uint64_t_s_u
#define safe_div_func_uint64_t_s_s
#define safe_mod_func_int8_t_u_u
#define safe_mod_func_int8_t_u_s
#define safe_mod_func_int8_t_s_u
#define safe_mod_func_int8_t_s_s
#define safe_mod_func_uint8_t_u_u
#define safe_mod_func_uint8_t_u_s
#define safe_mod_func_uint8_t_s_u
#define safe_mod_func_uint8_t_s_s
#define safe_mod_func_int16_t_u_u
#define safe_mod_func_int16_t_u_s
#define safe_mod_func_int16_t_s_u
#define safe_mod_func_int16_t_s_s
#define safe_mod_func_uint16_t_u_u
#define safe_mod_func_uint16_t_u_s
#define safe_mod_func_uint16_t_s_u
#define safe_mod_func_uint16_t_s_s
#define safe_mod_func_int32_t_u_u
#define safe_mod_func_int32_t_u_s
#define safe_mod_func_int32_t_s_u
#define safe_mod_func_int32_t_s_s
#define safe_mod_func_uint32_t_u_u
#define safe_mod_func_uint32_t_u_s
#define safe_mod_func_uint32_t_s_u
#define safe_mod_func_uint32_t_s_s
#define safe_mod_func_int64_t_u_u
#define safe_mod_func_int64_t_u_s
#define safe_mod_func_int64_t_s_u
#define safe_mod_func_int64_t_s_s
#define safe_mod_func_uint64_t_u_u
#define safe_mod_func_uint64_t_u_s
#define safe_mod_func_uint64_t_s_u
#define safe_mod_func_uint64_t_s_s
#define safe_lshift_func_int8_t_u_u
#define safe_lshift_func_int8_t_u_s
#define safe_lshift_func_int8_t_s_u
#define safe_lshift_func_int8_t_s_s
#define safe_lshift_func_uint8_t_u_u
#define safe_lshift_func_uint8_t_u_s
#define safe_lshift_func_uint8_t_s_u
#define safe_lshift_func_uint8_t_s_s
#define safe_lshift_func_int16_t_u_u
#define safe_lshift_func_int16_t_u_s
#define safe_lshift_func_int16_t_s_u
#define safe_lshift_func_int16_t_s_s
#define safe_lshift_func_uint16_t_u_u
#define safe_lshift_func_uint16_t_u_s
#define safe_lshift_func_uint16_t_s_u
#define safe_lshift_func_uint16_t_s_s
#define safe_lshift_func_int32_t_u_u
#define safe_lshift_func_int32_t_u_s
#define safe_lshift_func_int32_t_s_u
#define safe_lshift_func_int32_t_s_s
#define safe_lshift_func_uint32_t_u_u
#define safe_lshift_func_uint32_t_u_s
#define safe_lshift_func_uint32_t_s_u
#define safe_lshift_func_uint32_t_s_s
#define safe_lshift_func_int64_t_u_u
#define safe_lshift_func_int64_t_u_s
#define safe_lshift_func_int64_t_s_u
#define safe_lshift_func_int64_t_s_s
#define safe_lshift_func_uint64_t_u_u
#define safe_lshift_func_uint64_t_u_s
#define safe_lshift_func_uint64_t_s_u
#define safe_lshift_func_uint64_t_s_s
#define safe_rshift_func_int8_t_u_u
#define safe_rshift_func_int8_t_u_s
#define safe_rshift_func_int8_t_s_u
#define safe_rshift_func_int8_t_s_s
#define safe_rshift_func_uint8_t_u_u
#define safe_rshift_func_uint8_t_u_s
#define safe_rshift_func_uint8_t_s_u
#define safe_rshift_func_uint8_t_s_s
#define safe_rshift_func_int16_t_u_u
#define safe_rshift_func_int16_t_u_s
#define safe_rshift_func_int16_t_s_u
#define safe_rshift_func_int16_t_s_s
#define safe_rshift_func_uint16_t_u_u
#define safe_rshift_func_uint16_t_u_s
#define safe_rshift_func_uint16_t_s_u
#define safe_rshift_func_uint16_t_s_s
#define safe_rshift_func_int32_t_u_u
#define safe_rshift_func_int32_t_u_s
#define safe_rshift_func_int32_t_s_u
#define safe_rshift_func_int32_t_s_s
#define safe_rshift_func_uint32_t_u_u
#define safe_rshift_func_uint32_t_u_s
#define safe_rshift_func_uint32_t_s_u
#define safe_rshift_func_uint32_t_s_s
#define safe_rshift_func_int64_t_u_u
#define safe_rshift_func_int64_t_u_s
#define safe_rshift_func_int64_t_s_u
#define safe_rshift_func_int64_t_s_s
#define safe_rshift_func_uint64_t_u_u
#define safe_rshift_func_uint64_t_u_s
#define safe_rshift_func_uint64_t_s_u
#define safe_rshift_func_uint64_t_s_s
#define safe_unary_minus_func_int8_t_u
#define safe_unary_minus_func_int8_t_s
#define safe_unary_minus_func_uint8_t_u
#define safe_unary_minus_func_uint8_t_s
#define safe_unary_minus_func_int16_t_u
#define safe_unary_minus_func_int16_t_s
#define safe_unary_minus_func_uint16_t_u
#define safe_unary_minus_func_uint16_t_s
#define safe_unary_minus_func_int32_t_u
#define safe_unary_minus_func_int32_t_s
#define safe_unary_minus_func_uint32_t_u
#define safe_unary_minus_func_uint32_t_s
#define safe_unary_minus_func_int64_t_u
#define safe_unary_minus_func_int64_t_s
#define safe_unary_minus_func_uint64_t_u
#define safe_unary_minus_func_uint64_t_s
