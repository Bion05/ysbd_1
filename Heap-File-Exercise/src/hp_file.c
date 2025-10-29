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
  header.totalRecords = 0;
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
  BF_Block_Init(&block);
  // Άνοιγμα του αρχείου
  CALL_BF(BF_OpenFile(fileName, file_handle));

  // Φόρτωση του πρώτου block
  CALL_BF(BF_GetBlock(*file_handle, 0, block));


  // Αντιγραφή δεδομένων σε δομή HeapFileHeader
  char *data = BF_Block_GetData(block);
  *header_info = malloc(sizeof(HeapFileHeader));
  memcpy(*header_info, data, sizeof(HeapFileHeader));
  //Έλεγχος οτι είναι Heap File
  if(strcmp((*header_info)->filetype, "HEAP") != 0){
    fprintf(stderr, "HeapFile_Open: Not Heap file\n");
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
  CALL_BF(BF_GetBlock(file_handle, 0, block));
  char *data = BF_Block_GetData(block);
  memset(data,0,BF_BLOCK_SIZE);
  memcpy(data, hp_info, sizeof(HeapFileHeader));
  
  BF_Block_SetDirty(block);
  CALL_BF(BF_UnpinBlock(block));
  BF_Block_Destroy(&block);
  CALL_BF(BF_CloseFile(file_handle));
  return 1;
}

int HeapFile_InsertRecord(int file_handle, HeapFileHeader *hp_info, const Record record)
{
  BF_Block *block;
  BF_Block_Init(&block);
  int blocks_number = hp_info->totalBlocks;
  char *data;
  int rpb = BF_BLOCK_SIZE/sizeof(Record);
  int rinbfinal = hp_info->totalRecords - (blocks_number-2)*rpb;
  
  // Εντοπισμος του τελευταίου block
  CALL_BF(BF_GetBlock(file_handle,blocks_number-1, block));
  data = BF_Block_GetData(block);

  // Αν υπάρχει χώρος προσθέτουμε την εγγραφή
  if(rinbfinal<rpb && blocks_number>1){
    data += (BF_BLOCK_SIZE - rinbfinal*sizeof(record));
    memcpy(data,&record,sizeof(Record));
    BF_Block_SetDirty(block);
    CALL_BF(BF_UnpinBlock(block));
    hp_info->totalRecords+=1;
    BF_Block_Destroy(&block);
    return 1;
  }

  // Αν το τελευταίο block είναι γεμάτο δημιουργούμε νέο block
  CALL_BF(BF_UnpinBlock(block));
  CALL_BF(BF_AllocateBlock(file_handle, block));
  data = BF_Block_GetData(block);
  memset(data, 0, BF_BLOCK_SIZE);
  memcpy(data,&record,sizeof(Record));
  BF_Block_SetDirty(block);
  CALL_BF(BF_UnpinBlock(block));
  hp_info->totalBlocks+=1;
  hp_info->totalRecords+=1;
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
  int rpb = BF_BLOCK_SIZE/sizeof(Record);
  int rinbfinal = header_info->totalRecords - (header_info->totalBlocks-2)*rpb;
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
  out.current_block = 0;
  out.current_record = 0;
  BF_UnpinBlock(block);
  BF_Block_Destroy(&block);
  return out;
}


int HeapFile_GetNextRecord(    HeapFileIterator* heap_iterator, Record** record)
{
  if(heap_iterator->header->totalRecords==0){ //empty file at iterator creation
    *record = NULL;
    printf("\nfile empty\n");
    return 0;
  }
  if(heap_iterator->current_block == 0){ //no initial matching record at iterator creation
    *record = NULL;
    printf("\nno matching records in file\n");
    return 0;
  }

  if(heap_iterator->current_block == -1){ //final matching record at iterator creation reached in previous call
    *record = NULL;
    printf("\nEOF reached\n");
    return 0;
  }

  int rpb = BF_BLOCK_SIZE/sizeof(Record);
  int rinbfinal = heap_iterator->header->totalRecords - (heap_iterator->header->totalBlocks-2)*rpb;
  
  BF_Block *block; 
  BF_Block_Init(&block);
  CALL_BF(BF_GetBlock(heap_iterator->file_handle,heap_iterator->current_block,block)); 
  char *data = BF_Block_GetData(block);

  //extract current record
  Record *records = (Record*) data;
  *record = malloc(sizeof(Record));
  memset(*record,0,sizeof(Record));
  memcpy(*record,&records[heap_iterator->current_record],sizeof(Record));
  heap_iterator->current_record++;
  CALL_BF(BF_UnpinBlock(block));  

  //update iterator for next call
  for(int i=heap_iterator->current_block; i<heap_iterator->header->totalBlocks; i++){
    heap_iterator->current_block = i;
    int rinb = (i<heap_iterator->header->totalBlocks-1) ? rpb : rinbfinal;
    BF_Block_Init(&block);
    BF_GetBlock(heap_iterator->file_handle,i,block); 
    char* data = BF_Block_GetData(block);
    Record *records = (Record*) data;
    for(int j=heap_iterator->current_record;j<rinb;j++){
      if(records[j].id == heap_iterator->id){ // && records[j].id == -1 if we implement a no filter option 
        heap_iterator->current_record = j;
        BF_UnpinBlock(block);
        BF_Block_Destroy(&block);
        return 1;
      }
    }
    heap_iterator->current_record = 0;
    BF_UnpinBlock(block);
  }
  //no other matching records left
  heap_iterator->current_block = -1;
  heap_iterator->current_record = 0;
  BF_Block_Destroy(&block);
  return 1;
}

