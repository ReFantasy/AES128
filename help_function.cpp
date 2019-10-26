/******************************************************************************************
 *
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2019  Tan DongLiang @cust
 *
 ******************************************************************************************/
#include "help_function.h"
#include <string>

byte ExtractByte(const word &w, size_t byte_index)
{
	if ((byte_index + 1) * 8 > w.size())
		return byte{ 0x0 };

	std::string str = w.to_string();
	return std::bitset<8>(str.substr(byte_index * 8, 8));
}
