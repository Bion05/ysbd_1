#ifndef HP_FILE_STRUCTS_H
#define HP_FILE_STRUCTS_H

#include <record.h>

/**
 * @file hp_file_structs.h
 * @brief Data structures for heap file management
 */

/* -------------------------------------------------------------------------- */
/*                              Data Structures                               */
/* -------------------------------------------------------------------------- */

/**
 * @brief Heap file header containing metadata about the file organization
 */
typedef struct HeapFileHeader {
    char filetype[8];
    int totalRecords;
    int totalBlocks;
} HeapFileHeader;

/**
 * @brief Iterator for scanning through records in a heap file
 */
typedef struct HeapFileIterator{
    int file_handle;
    int current_block; // 0-indexed 
    int current_record; //0-indexed
    int rinb; //records in current block
    HeapFileHeader *header;
    int id;
} HeapFileIterator;


#endif /* HP_FILE_STRUCTS_H */
