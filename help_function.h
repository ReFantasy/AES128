﻿/******************************************************************************************
 *
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2019  Tan DongLiang @cust
 *
 ******************************************************************************************/
#ifndef __S_BOX_H__
#define __S_BOX_H__
#include <iostream>
#include <bitset>
using byte = std::bitset<8>;
using word = std::bitset<32>;

/*
 * 将4个byte组成一个word
 */
word Word(const byte &b1, const byte &b2, const byte &b3, const byte &b4);

/** \brief 从字中抽取字节元素
 *  \param[in] w 包含若干字节的字
 *  \param[in] byte_index 抽取的字节位置
 *  \return 抽取的字节
 */
byte ExtractByte(const word &w, size_t byte_index);


/*
 * S-box transformation table
 */
const uint8_t s_box[16][16] = {

	// 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f

	{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, // 0

	{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, // 1

	{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, // 2

	{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, // 3

	{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, // 4

	{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, // 5

	{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, // 6

	{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, // 7

	{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, // 8

	{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, // 9

	{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, // a

	{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, // b

	{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, // c

	{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, // d

	{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, // e

	{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };// f



/*
 * Inverse S-box transformation table
 */

const uint8_t inv_s_box[16][16] = {

	// 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f

	{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb}, // 0

	{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, // 1

	{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e}, // 2

	{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, // 3

	{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92}, // 4

	{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, // 5

	{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06}, // 6

	{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b}, // 7

	{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73}, // 8

	{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e}, // 9

	{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b}, // a

	{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4}, // b

	{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, // c

	{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef}, // d

	{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, // e

	{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} };// f


/** \brief Print Array
 *  \param[in] T data type
 *  \param[in] M rows of array
 *  \param[in] N cols of array
 *  \return
 */
template<typename T, int M, int N>
void PrintArray(const T(&a)[M][N])
{
	printf("Array: %d rows, %d cols \n", M, N);
	for (int i = 0; i < M; i++)
	{
		for (int j = 0; j < N; j++)
		{
			//std::cout << std::hex << a[i][j] << " ";
			printf("%2X ", a[i][j]);
		}
		cout << endl;
	}
}

/*
 *  打印数组
 */
template<int M, int N>
void PrintArray(const byte(&a)[M][N])
{
	printf("Array: %d rows, %d cols \n", M, N);
	for (int i = 0; i < M; i++)
	{
		for (int j = 0; j < N; j++)
		{
			//std::cout << std::hex << a[i][j].to_ullong() << " ";
			printf("%2X ", a[i][j].to_ullong());
		}
		std::cout << std::endl;
	}
	std::cout << std::endl;
}

template<int N>
void PrintArray(const byte(&a)[N])
{
	printf("Array: %d\n", N);

	for (int j = 0; j < N; j++)
	{
		//std::cout << std::hex << a[j].to_ullong() << " ";
		printf("%2X ", a[j].to_ullong());
	}
	std::cout << std::endl;

}

/*
 * 按位循环左移
 *
 */
template<int N>
auto CircleShiftToLeftByBits(const std::bitset<N> data, int bits)->std::bitset<N>
{
	std::bitset<N> tmp_data = data;
	int all_bits = tmp_data.size();
	int shift_bits = bits % all_bits;

	std::bitset<N> R = (tmp_data >> (all_bits - shift_bits));
	std::bitset<N> L = tmp_data << shift_bits;
	return (R | L);
}


template<int N>
auto CircleShiftToRightByBits(const std::bitset<N> data, int bits)->std::bitset<N>
{
	int all_bits = data.size();
	int shift_bits = bits % all_bits;
	// 等价于左移 all_bits-shift_bits
	return CircleShiftToLeftByBits(data, all_bits - shift_bits);
}

template<int N>
void CircleShiftOneByteToLeft(byte(&data)[N])
{
	byte v = data[0];
	for (int i = 1; i < N; i++)
	{
		data[i - 1] = data[i];
	}
	data[N - 1] = v;
}

template<int N>
void CircleShiftToLeftByBytes(byte(&data)[N], int bytes)
{
	for (int i = 0; i < bytes; i++)
	{
		CircleShiftOneByteToLeft(data);
	}
}

template<typename T, int M, int N>
void ArrayCopy(T(&dst)[M][N], T(&src)[M][N])
{
	for (int i = 0; i < M; i++)
	{
		for (int j = 0; j < N; j++)
		{
			dst[i][j] = src[i][j];
		}
	}
}

#endif//__S_BOX_H__
