#include "pch.h"
#include <iostream>
#include <conio.h>
#include <utility>
#include <vector>
#include <fstream>
#include <string>

typedef std::pair<unsigned int, unsigned int> IDADif;
typedef std::pair<unsigned int, IDADif> IDAEntry;

int main()
{
	if (__argc != 4)
	{
		std::cout << "Usage: <ida .dif file> <.exe file> <revert>" << std::endl;
		return 0;
	}

	std::string diff_fname(__argv[1]);
	std::string exe_fname(__argv[2]);
	bool revert = std::string(__argv[3]).compare("true") == 0;	
	bool verbose = true;

	std::vector<IDAEntry> entries = std::vector<IDAEntry>();

	std::ifstream diff_file(diff_fname.c_str());
	if (!diff_file.good())
	{
		std::cout << "Failed to load diff file: " << diff_fname << std::endl;
		return 1;
	}

	FILE* efile;
	int result = fopen_s(&efile, exe_fname.c_str(), "r+");

	if (efile == NULL)
	{
		std::cout << "Failed to load exe file: " << exe_fname << std::endl;
		std::cout << "Reason: fopen_s returns error code: " << result << (result == 13 ? " (Access Denied)" : "") << std::endl;
		return 1;
	}

	int lineNumber = 0;
	std::string line = "";
	while (std::getline(diff_file, line))
	{
		if (lineNumber < 3)
		{
			lineNumber++;
			continue;
		}	

		std::string attributes[3];
		std::size_t address_delim = line.find(':');
		if(address_delim == std::string::npos)
		{
			std::cout << "Failed to extract address data from diff file (ERROR 2)" << std::endl;
			return 2;
		}

		attributes[0] = std::string(line.substr(0, address_delim).c_str());
		line.erase(0, address_delim + 2); //skip over extra space

		std::size_t bbyte_delim = line.find(char(32));

		if (bbyte_delim == std::string::npos)
		{
			std::cout << "Failed to extract patch byte data from diff file (ERROR 3)" << std::endl;
			return 3;
		}
		attributes[1] = std::string(line.substr(0, bbyte_delim).c_str());
		line.erase(0, bbyte_delim + 1);

		attributes[2] = std::string(line.substr(0, 2).c_str());

		unsigned int address = std::stoul(attributes[0], nullptr, 16);
		unsigned int before_byte = std::stoul(attributes[1], nullptr, 16);
		unsigned int after_byte = std::stoul(attributes[2], nullptr, 16);
		entries.push_back(IDAEntry(address, IDADif(before_byte, after_byte)));
	}

	diff_file.close();

	std::cout << "Loaded " << entries.size() << " entries!" << std::endl;
	if (revert)
		std::cout << "Reverting the program to the original state ..." << std::endl;
	else
		std::cout << "Applying patches..." << std::endl;

	for (IDAEntry entry : entries)
	{
		fseek(efile, entry.first, SEEK_SET);
		fprintf(efile, "%c", revert ? entry.second.first : entry.second.second);
		//std::cout << "Address: " << std::hex << entry.first << ", Before: " << entry.second.first << ", After: " << entry.second.second << std::endl;
	}
	fclose(efile);

	std::cout << "Finished patching!" << std::endl;		

	return 0;
}