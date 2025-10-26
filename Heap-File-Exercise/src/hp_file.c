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
  CALL_BF(BF_AllocateBlock(file_handle, block));

  // Εγγραφές ανα block
  header.record_size = sizeof(Record);
  header.records_per_blocks = (BF_BLOCK_SIZE - sizeof(int)) / sizeof(Record);
  strncpy(header.filetype, "HEAP", sizeof(header.filetype) - 1);

  // Κεφαλίδα
  char *data = BF_Block_GetData(block);
  memcpy(data, &header, sizeof(HeapFileHeader));

  // Unpined και αποδέσμευση
  BF_Block_SetDirty(block);
  CALL_BF(BF_UnpinBlock(block));
  BF_Block_Destroy(&block);

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
  if(*header_info == NULL){
    fprintf(stderr, "HeapFile_Open: Memory allocation failed\n");
    CALL_BF(BF_UnpinBlock(block));
    BF_Block_Destroy(&block);
    return 0;
  }
  memcpy(*header_info, data, sizeof(HeapFileHeader));

  // Έλεγχος οτι είναι Heap File
  if(strcmp((*header_info)->filetype, "HEAP") != 0){
    fprintf(stderr, "HeapFile_Open: Not Heap file\n");
    free(*header_info);
    *header_info = NULL;
    CALL_BF(BF_UnpinBlock(block));
    BF_Block_Destroy(&block);
    CALL_BF(BF_CloseFile(*file_handle));
    return 0;
  }

  CALL_BF(BF_UnpinBlock(block));
  BF_Block_Destroy(&block);

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
  BF_Block_Init(&block);
  int blocks_number;
  

  // Αριθμός blocks
  if(BF_GetBlockCounter(file_handle, &blocks_number) != BF_OK){
    BF_Block_Destroy(&block);
    return 0;
  }

  // Αν υπαρχει μόνο το header block δημιουργούμε νέο block
  if(blocks_number == 1){
    if(BF_AllocateBlock(file_handle, block) != BF_OK){
      BF_Block_Destroy(&block);
      return 0;
    }
    
    void *data = BF_Block_GetData(block);
    int record_count = 0;
    memcpy(data, &record_count, sizeof(int));
    BF_Block_SetDirty(block);
    CALL_BF(BF_UnpinBlock(block));
    blocks_number++;
  }

  // Ελεγχος διπλότυπης εγγραφής
  for(int i = 1; i < blocks_number; i++){
    if(BF_GetBlock(file_handle, i, block) != BF_OK) continue;

    void *data = BF_Block_GetData(block);
    int record_count;
    memcpy(&record_count, data, sizeof(int));
    Record *records_start = (Record*)(data + sizeof(int));

    for(int j = 0; j < record_count; j++){
      if(records_start[j].id == record.id){
        printf("Record with id %d already exists!\n", record.id);
        CALL_BF(BF_UnpinBlock(block));
        BF_Block_Destroy(&block);
        return 0;
      }
    }
    CALL_BF(BF_UnpinBlock(block));
  }

  // Εντοπισμος του τελευταίου block
  int last_block = blocks_number - 1;
  if(BF_GetBlock(file_handle, last_block, block) != BF_OK){
    BF_Block_Destroy(&block);
    return 0;
  }

  void *data = BF_Block_GetData(block);
  int record_count;
  memcpy(&record_count, data, sizeof(int));

  // Αν υπάρχει χώρος προσθέτουμε την εγγραφή
  if(record_count < hp_info->records_per_blocks){
    Record *recordsStart = (Record*)(data + sizeof(int));
    recordsStart[record_count] = record;
    record_count++;
    memcpy(data, &record_count, sizeof(int));
    BF_Block_SetDirty(block);
    CALL_BF(BF_UnpinBlock(block));
    BF_Block_Destroy(&block);

    return 1;
  }

  // Αν το τελευταίο block είναι γεμάτο δημιουργούμε νέο block
  CALL_BF(BF_UnpinBlock(block));

  if(BF_AllocateBlock(file_handle, block) != BF_OK){
    BF_Block_Destroy(&block);
    return 0;
  }

  void *new_data = BF_Block_GetData(block);
  int new_count = 1;
  memcpy(new_data, &new_count, sizeof(int));
  memcpy(new_data + sizeof(int), &record, sizeof(Record));

  BF_Block_SetDirty(block);
  CALL_BF(BF_UnpinBlock(block));
  BF_Block_Destroy(&block);

  return 1;

}


HeapFileIterator HeapFile_CreateIterator(    int file_handle, HeapFileHeader* header_info, int id)
{
  HeapFileIterator out;
  return out;
}


int HeapFile_GetNextRecord(    HeapFileIterator* heap_iterator, Record** record)
{
    * record=NULL;
    return 1;
}

