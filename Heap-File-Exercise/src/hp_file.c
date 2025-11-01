#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bf.h"
#include "hp_file_structs.h"
#include "record.h"

#define CALL_BF(call)         \
  {                           \
    BF_ErrorCode code = call; \
    if (code != BF_OK)        \
    {                         \
      BF_PrintError(code);    \
      return 0;        \
    }                         \
  }

int HeapFile_Create(const char* fileName){
  int file_handle;
  BF_Block *block;
  HeapFileHeader header;

  // Create a new file
  CALL_BF(BF_CreateFile(fileName));

  // Open the file so we can write the header block
  CALL_BF(BF_OpenFile(fileName, &file_handle));

  // Allocate and initialize the first block
  BF_Block_Init(&block);
  BF_AllocateBlock(file_handle, block);

  // Initialize header metadata
  header.totalRecords = 0;
  header.totalBlocks = 1;
  memset(header.filetype, 0, sizeof(header.filetype));
  memcpy(header.filetype, "HEAP", 4);

  // Write the header data into the block
  char *data = BF_Block_GetData(block);
  memset(data, 0, BF_BLOCK_SIZE);
  memcpy(data, &header, sizeof(HeapFileHeader));

  // Mark block as modified and unpin it
  BF_Block_SetDirty(block);
  CALL_BF(BF_UnpinBlock(block));
  CALL_BF(BF_CloseFile(file_handle));

  return 1;
}

int HeapFile_Open(const char *fileName, int *file_handle, HeapFileHeader** header_info)
{
  BF_Block *block;
  BF_Block_Init(&block);

  // Open file
  CALL_BF(BF_OpenFile(fileName, file_handle));

  // Read the first block
  CALL_BF(BF_GetBlock(*file_handle, 0, block));

  // Copy header data into a HeapFileHeader structure  
  char *data = BF_Block_GetData(block);
  *header_info = malloc(sizeof(HeapFileHeader));
  memcpy(*header_info, data, sizeof(HeapFileHeader));

  // Verify that the file type mathes "Heap"
  if(strcmp((*header_info)->filetype, "HEAP") != 0){
    fprintf(stderr, "HeapFile_Open: Not Heap file\n");
    free(*header_info);
    *header_info = NULL;
    CALL_BF(BF_UnpinBlock(block));
    CALL_BF(BF_CloseFile(*file_handle));
    BF_Block_Destroy(&block);

    return 0;
  }

  CALL_BF(BF_UnpinBlock(block));
  BF_Block_Destroy(&block);

  return 1;
}

int HeapFile_Close(int file_handle, HeapFileHeader *hp_info)
{
  BF_Block *block;
  BF_Block_Init(&block);

  if(hp_info != NULL)free(hp_info);
  
  CALL_BF(BF_CloseFile(file_handle));

  return 1;
}

int HeapFile_InsertRecord(int file_handle, HeapFileHeader *hp_info, const Record record)
{
  BF_Block *block;
  BF_Block_Init(&block);

  int blocks_number = hp_info->totalBlocks;
  char *data;
  int rpb = BF_BLOCK_SIZE/sizeof(Record);   // records per block
  int rinbfinal = hp_info->totalRecords - (blocks_number-2)*rpb;    // records in last block
  
  // Get the last data block
  CALL_BF(BF_GetBlock(file_handle,blocks_number-1, block));
  data = BF_Block_GetData(block);

  // If the last block has space insert record
  if(rinbfinal<rpb && blocks_number>1){
    data +=rinbfinal*sizeof(Record);
    memcpy(data,&record,sizeof(Record));

    BF_Block_SetDirty(block);
    CALL_BF(BF_UnpinBlock(block));
    hp_info->totalRecords+=1;

    // Retrieve the header block
    CALL_BF(BF_GetBlock(file_handle, 0, block));
    data = BF_Block_GetData(block);

    // Update the header with the current metadata
    memset(data,0,BF_BLOCK_SIZE);
    memcpy(data, hp_info, sizeof(HeapFileHeader));
    
    // Mark the block as dirty and close
    BF_Block_SetDirty(block);
    CALL_BF(BF_UnpinBlock(block));
    BF_Block_Destroy(&block);

    return 1;
  }

  // If the last block is full allocate a new one
  CALL_BF(BF_UnpinBlock(block));
  CALL_BF(BF_AllocateBlock(file_handle, block));
  data = BF_Block_GetData(block);
  memset(data, 0, BF_BLOCK_SIZE);
  memcpy(data,&record,sizeof(Record));

  BF_Block_SetDirty(block);
  CALL_BF(BF_UnpinBlock(block));

  // Update metadata
  hp_info->totalBlocks+=1;
  hp_info->totalRecords+=1;

  // Retrieve the header block
  CALL_BF(BF_GetBlock(file_handle, 0, block));
  data = BF_Block_GetData(block);

  // Update the header with the current metadata
  memset(data,0,BF_BLOCK_SIZE);
  memcpy(data, hp_info, sizeof(HeapFileHeader));
  
  // Mark the block as dirty and close
  BF_Block_SetDirty(block);
  CALL_BF(BF_UnpinBlock(block));
  BF_Block_Destroy(&block);
  return 1;
}

HeapFileIterator HeapFile_CreateIterator(    int file_handle, HeapFileHeader* header_info, int id)
{
  HeapFileIterator out;
  out.file_handle = file_handle;
  out.current_block = 0;
  out.current_record = 0;
  out.header = header_info;
  out.id = id;

  BF_Block *block; 
  BF_Block_Init(&block);

  int rpb = BF_BLOCK_SIZE/sizeof(Record);   // records per block
  int rinbfinal = header_info->totalRecords - (header_info->totalBlocks-2)*rpb;   // records in last block

  // Search through all blocks for the first record with maching id
  for(int i=1; i<header_info->totalBlocks; i++){
    out.current_block = i;
    int rinb = (i<header_info->totalBlocks-1) ? rpb : rinbfinal;
    BF_GetBlock(file_handle,i,block); 
    char* data = BF_Block_GetData(block);
    Record *records = (Record*) data;

    for(int j=0;j<rinb;j++){
      if(records[j].id == id){ // && records[j].id == -1 if we implement a no filter option 
        out.current_record = j;
        BF_UnpinBlock(block);
        BF_Block_Destroy(&block);
        return out;
      }
    }
    
    out.current_record = 0;
    BF_UnpinBlock(block);
  }

  //No matching record
  out.current_block = 0;
  out.current_record = 0;

  BF_Block_Destroy(&block);
  return out;
}


int HeapFile_GetNextRecord(    HeapFileIterator* heap_iterator, Record** record)
{
  // Empty file at iterator creation
  if(heap_iterator->header->totalRecords==0){ 
    *record = NULL;
    printf("\nfile empty\n");
    return 0;
  }

  // No initial matching record at iterator creation
  if(heap_iterator->current_block == 0){ 
    *record = NULL;
    printf("\nno matching records in file\n");
    return 0;
  }

  // Final matching record at iterator creation reached in previous call
  if(heap_iterator->current_block == -1){ 
    *record = NULL;
    printf("\nEOF reached\n");
    return 0;
  }

  int rpb = BF_BLOCK_SIZE/sizeof(Record);   // records per block
  int rinbfinal = heap_iterator->header->totalRecords - (heap_iterator->header->totalBlocks-2)*rpb;   // records in last block
  
  BF_Block *block; 
  BF_Block_Init(&block);

  // Load current block
  CALL_BF(BF_GetBlock(heap_iterator->file_handle,heap_iterator->current_block,block)); 
  char *data = BF_Block_GetData(block);

  // Extract current record
  Record *records = (Record*) data;
  *record = malloc(sizeof(Record));
  memset(*record,0,sizeof(Record));
  memcpy(*record,&records[heap_iterator->current_record],sizeof(Record));
  heap_iterator->current_record++;
  CALL_BF(BF_UnpinBlock(block));  

  // Update iterator for next call
  for(int i=heap_iterator->current_block; i<heap_iterator->header->totalBlocks; i++){
    heap_iterator->current_block = i;
    int rinb = (i<heap_iterator->header->totalBlocks-1) ? rpb : rinbfinal;
    CALL_BF(BF_GetBlock(heap_iterator->file_handle,i,block)); 
    char* data = BF_Block_GetData(block);
    Record *records = (Record*) data;

    for(int j=heap_iterator->current_record;j<rinb;j++){
      if(records[j].id == heap_iterator->id){
        heap_iterator->current_record = j;
        CALL_BF(BF_UnpinBlock(block));
        BF_Block_Destroy(&block);
        return 1;
      }
    }
    heap_iterator->current_record = 0;
    CALL_BF(BF_UnpinBlock(block));
  }

  // No other matching records left
  heap_iterator->current_block = -1;
  heap_iterator->current_record = 0;

  BF_Block_Destroy(&block);
  return 1;
}


