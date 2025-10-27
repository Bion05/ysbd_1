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

  // Δημιουργία νέου αρχείου
  CALL_BF(BF_CreateFile(fileName));

  // Άνοιγμα αρχείου για να γράψουμε το header
  CALL_BF(BF_OpenFile(fileName, &file_handle));

  // Δημιουργία block
  BF_Block_Init(&block);
  BF_AllocateBlock(file_handle, block);

  // Εγγραφές ανα block
  header.totalRecords = 1;
  header.totalBlocks = 1;
  strncpy(header.filetype, "HEAP", sizeof(header.filetype) - 1);

  // Κεφαλίδα
  char *data = BF_Block_GetData(block);
  memset(data, 0, BF_BLOCK_SIZE);
  memcpy(data, &header, sizeof(HeapFileHeader));

  // αποδέσμευση
  BF_Block_SetDirty(block);
  CALL_BF(BF_UnpinBlock(block));

  // Κλήσιμο αρχείου
  CALL_BF(BF_CloseFile(file_handle));

  return 1;
}

int HeapFile_Open(const char *fileName, int *file_handle, HeapFileHeader** header_info)
{
  BF_Block *block;
  // Άνοιγμα του αρχείου
  CALL_BF(BF_OpenFile(fileName, file_handle));

  // Φόρτωση του πρώτου block
  CALL_BF(BF_GetBlock(*file_handle, 0, block));

  // Έλεγχος οτι είναι Heap File
  if(strcmp((*header_info)->filetype, "HEAP") != 0){
    fprintf(stderr, "HeapFile_Open: Not Heap file\n");
    *header_info = NULL;
    CALL_BF(BF_UnpinBlock(block));
    CALL_BF(BF_CloseFile(*file_handle));
    return 0;
  }

  // Αντιγραφή δεδομένων σε δομή HeapFileHeader
  char *data = BF_Block_GetData(block);
  *header_info = malloc(sizeof(HeapFileHeader));
  if(*header_info == NULL){
    fprintf(stderr, "HeapFile_Open: Memory allocation failed\n");
    CALL_BF(BF_UnpinBlock(block));    
    return 0;
  }
  memcpy(*header_info, data, sizeof(HeapFileHeader));

  CALL_BF(BF_UnpinBlock(block));

  return 1;
}

int HeapFile_Close(int file_handle, HeapFileHeader *hp_info)
{
  CALL_BF(BF_CloseFile(file_handle));

  if(hp_info != NULL){
    free(hp_info);
  }

  return 1;
}

int HeapFile_InsertRecord(int file_handle, HeapFileHeader *hp_info, const Record record)
{
  BF_Block *block;
  int blocks_number = hp_info->totalBlocks;
  char *data;
  // Ελεγχος διπλότυπης εγγραφής
  unsigned long available_space =(BF_BLOCK_SIZE*blocks_number) - (sizeof(Record)*hp_info->totalRecords) - sizeof(HeapFileHeader);
  for(int i = 0; i < blocks_number; i++){
    CALL_BF(BF_GetBlock(file_handle, i, block));
    data = BF_Block_GetData(block);
    int rpb = BF_BLOCK_SIZE/sizeof(Record);
    if(i==0){
      rpb = (BF_BLOCK_SIZE - sizeof(HeapFileHeader))/ sizeof(Record);
      data = data + sizeof(HeapFileHeader);
    }
    if(i == blocks_number - 1)rpb = rpb - (available_space/sizeof(Record));
    Record *records = (Record *) data;
    CALL_BF(BF_UnpinBlock(block));
    for(int j=0;j<rpb;j++){
      if(records[j].id == record.id){
          printf("Record with id %d already exists!\n", record.id);
          return 0;
        }
      }
    }
    

  // Εντοπισμος του τελευταίου block
  if(BF_GetBlock(file_handle,blocks_number-1, block) != BF_OK){
    return 0;
  }

    data = BF_Block_GetData(block);
    // Αν υπάρχει χώρος προσθέτουμε την εγγραφή
    if(sizeof(record)<=available_space){
      data = data + (BF_BLOCK_SIZE - available_space);
      Record* slot = (Record *)data;
      *slot = record;
      BF_Block_SetDirty(block);
      CALL_BF(BF_UnpinBlock(block));
      hp_info->totalRecords +=1;
      return 1;
  }

  // Αν το τελευταίο block είναι γεμάτο δημιουργούμε νέο block
  CALL_BF(BF_UnpinBlock(block));

  BF_Block_Init(&block);
  BF_AllocateBlock(file_handle, block);
  data = BF_Block_GetData(block);
  Record* slot = (Record *)data;
  *slot = record;
  BF_Block_SetDirty(block);
  CALL_BF(BF_UnpinBlock(block));
  hp_info->totalBlocks+=1;
  hp_info->totalRecords+=1;
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
  return out;
}


int HeapFile_GetNextRecord(    HeapFileIterator* heap_iterator, Record** record)
{
  if(heap_iterator->header->totalRecords==0)return 0;
  
  int initial_block = heap_iterator->current_block;
  int initial_record = heap_iterator->current_record;
  
  BF_Block *block; 
  CALL_BF(BF_GetBlock(heap_iterator->file_handle,heap_iterator->current_block,block)); 
  char *data = BF_Block_GetData(block);

  if(heap_iterator->current_block==0) data += sizeof(HeapFileHeader);
  Record *records = (Record*) data;
  *record = &records[heap_iterator->current_record];
  heap_iterator->current_record++;
  CALL_BF(BF_UnpinBlock(block));

  while(heap_iterator->current_block<heap_iterator->header->totalBlocks){
    int rpb0full = (BF_BLOCK_SIZE - sizeof(HeapFileHeader)) / sizeof(Record);
    int rpbfull = BF_BLOCK_SIZE/ sizeof(Record);
    int rinb = (heap_iterator->current_block<heap_iterator->header->totalBlocks-1) ? rpbfull : (heap_iterator->header->totalRecords - rpb0full - (heap_iterator->header->totalBlocks-2)*rpbfull);
    CALL_BF(BF_GetBlock(heap_iterator->file_handle,heap_iterator->current_block,block)); 
    data = BF_Block_GetData(block);
    if(heap_iterator->current_block==0) data += sizeof(HeapFileHeader);
    records = (Record*) data;
    for(int i=heap_iterator->current_record;i<rinb;i++){
      if(records[i].id == heap_iterator->id){ // && records[i].id == -1 if we implement a no filter option 
        heap_iterator->current_record = i;
        CALL_BF(BF_UnpinBlock(block));
        return 1;
      }
    }
    heap_iterator->current_block++;
    heap_iterator->current_record == 0;
    CALL_BF(BF_UnpinBlock(block));
  }
  heap_iterator->current_block = initial_block;
  heap_iterator->current_record = initial_record;
  return 0;
}

