#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <semaphore.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "ringbuffer.h"

#include <assert.h>
//#define DEBUG_CRC
//#define DEBUG_ESCAPING
//#define DEBUG_UN_ESCAPING
#define DEBUG_PROTOCOL_BYTES

#define SAMPLE_DEVICE_ID_BRDCST (0x0)
#define SAMPLE_DEVICE_ID_ADAS   (0x64)
#define SAMPLE_DEVICE_ID_DSM    (0x65)
#define SAMPLE_DEVICE_ID_TPMS   (0x66)
#define SAMPLE_DEVICE_ID_BSD    (0x67)

#define SAMPLE_CMD_QUERY            (0x2F)
#define SAMPLE_CMD_FACTORY_RESET    (0x30)
#define SAMPLE_CMD_SPEED_INFO       (0x31)
#define SAMPLE_CMD_DEVICE_INFO      (0x32)
#define SAMPLE_CMD_UPGRADE          (0x33)
#define SAMPLE_CMD_GET_PARAM        (0x34)
#define SAMPLE_CMD_SET_PARAM        (0x35)
#define SAMPLE_CMD_WARNING_REPORT   (0x36)
#define SAMPLE_CMD_REQ_STATUS       (0x37)
#define SAMPLE_CMD_UPLOAD_STATUS    (0x38)
#define SAMPLE_CMD_REQ_MM_DATA      (0x50)
#define SAMPLE_CMD_UPLOAD_MM_DATA   (0x51)
#define SAMPLE_CMD_SNAP_SHOT        (0x52)

#define SAMPLE_PROT_MAGIC       (0x7E)
#define SAMPLE_PROT_ESC_CHAR    (0x7D)

/**************cirbuf******************/
ringBuffer_typedef(unsigned char, intBuffer);
intBuffer myBuffer;
intBuffer* myBuffer_ptr;

//#define UPGRADE_FILE_PATH   "./auto_update_aescrypt-1.0.0.mpk"    
#define UPGRADE_FILE_PATH   "./auto_update.sh.mpk"    

static char test_ok;

sem_t sem;
typedef struct _sample_prot_header
{
    uint8_t     magic;
    uint8_t     checksum;
    uint16_t    version;
    uint16_t    vendor_id;
    uint8_t     device_id;
    uint8_t     cmd;
} __attribute__((packed)) sample_prot_header;

typedef struct _sample_mm_info
{
    uint8_t type;
    uint32_t id;
} __attribute__((packed)) sample_mm_info;



typedef struct _para_setting{

    uint8_t warning_speed_val;
    uint8_t warning_volume;
    uint8_t auto_photo_mode;
    uint16_t auto_photo_time_period;
    uint16_t auto_photo_distance_period;
    uint8_t photo_num;
    uint8_t photo_time_period;
    uint8_t image_Resolution;
    uint8_t video_Resolution;
    uint8_t reserve[9];

    uint8_t obstacle_distance_threshold;
    uint8_t obstacle_video_time;
    uint8_t obstacle_photo_num;
    uint8_t obstacle_photo_time_period;

    uint8_t FLC_time_threshold;
    uint8_t FLC_times_threshold;
    uint8_t FLC_video_time;
    uint8_t FLC_photo_num;
    uint8_t FLC_photo_time_period;

    uint8_t LDW_video_time;
    uint8_t LDW_photo_num;
    uint8_t LDW_photo_time_period;


    uint8_t FCW_time_threshold;
    uint8_t FCW_video_time;
    uint8_t FCW_photo_num;
    uint8_t FCW_photo_time_period;


    uint8_t PCW_time_threshold;
    uint8_t PCW_video_time;
    uint8_t PCW_photo_num;
    uint8_t PCW_photo_time_period;

    uint8_t HW_time_threshold;
    uint8_t HW_video_time;
    uint8_t HW_photo_num;
    uint8_t HW_photo_time_period;

    uint8_t TSR_photo_num;
    uint8_t TSR_photo_time_period;

    uint8_t reserve2[4];

} __attribute__((packed)) para_setting;


typedef struct _dsm_para_setting{

    //uint8_t Warn_SpeedThreshold;
    uint8_t warning_speed_val;
    uint8_t warning_volume;

    uint8_t auto_photo_mode;
    uint16_t auto_photo_time_period;
    uint16_t auto_photo_distance_period;

    uint8_t photo_num;
    uint8_t photo_time_period;

    uint8_t image_Resolution;
    uint8_t video_Resolution;
    uint8_t reserve[10];

    uint16_t Smoke_TimeIntervalThreshold;
    uint16_t Call_TimeIntervalThreshold;

    uint8_t FatigueDriv_VideoTime;
    uint8_t FatigueDriv_PhotoNum;
    uint8_t FatigueDriv_PhotoInterval;
    uint8_t FatigueDriv_resv;

    uint8_t CallingDriv_VideoTime;
    uint8_t CallingDriv_PhotoNum;
    uint8_t CallingDriv_PhotoInterval;

    uint8_t SmokingDriv_VideoTime;
    uint8_t SmokingDriv_PhotoNum;
    uint8_t SmokingDriv_PhotoInterval;

    uint8_t DistractionDriv_VideoTime;
    uint8_t DistractionDriv_PhotoNum;
    uint8_t DistractionDriv_PhotoInterval;

    uint8_t AbnormalDriv_VideoTime;
    uint8_t AbnormalDriv_PhotoNum;
    uint8_t AbnormalDriv_PhotoInterval;

    uint8_t reserve2[2];
} __attribute__((packed)) dsm_para_setting;


//para_setting par;
dsm_para_setting par;

typedef struct _sample_dev_info
{
    uint8_t     vendor_name_len;
    uint8_t     vendor_name[15];
    uint8_t     prod_code_len;
    uint8_t     prod_code[15];
    uint8_t     hw_ver_len;
    uint8_t     hw_ver[15];
    uint8_t     sw_ver_len;
    uint8_t     sw_ver[15];
    uint8_t     dev_id_len;
    uint8_t     dev_id[15];
    uint8_t     custom_code_len;
    uint8_t     custom_code[15];
} __attribute__((packed)) sample_dev_info;

#define SW_STATUS_BEGIN (0x0)
#define SW_STATUS_END   (0x1)
#define SW_STATUS_EVENT (0x10)
#define SW_TYPE_FCW     (0x1)
#define SW_TYPE_LDW     (0x2)
#define SW_TYPE_HW      (0x3)
#define SW_TYPE_PCW     (0x4)
#define SW_TYPE_FLC     (0x5)
#define SW_TYPE_TSRW    (0x6)
#define SW_TYPE_TSR     (0x10)
#define SW_TYPE_SNAP    (0x11)
#define SW_TSR_TYPE_SPEED   (0x1)
#define SW_TSR_TYPE_HIGHT   (0x2)
#define SW_TSR_TYPE_WEIGHT  (0x3)
typedef struct _sample_warning
{
    uint8_t     reserve0;
    uint8_t     status;
    uint8_t     type;
    uint8_t     reserve1;
    uint8_t     tsr_type;
    uint8_t     tsr_data;
    uint8_t     reserve2[2];
    uint8_t     mm_count;
} __attribute__((packed)) sample_warning;

#if 1
typedef struct __car_status {
    uint8_t		acc:1;
    uint8_t     left_signal:1;
    uint8_t     right_signal:1;
    uint8_t     wipers:1;
    uint8_t     inster:1;
    uint8_t     brakes:1;

    uint16_t     byte_resv:10;

} __attribute__((packed)) car_status_s;


typedef struct _real_time_data{

    uint8_t     car_speed;
    uint8_t     reserve1;
    uint32_t     mileage;
    uint8_t     reserve2[2];

    uint16_t	height;
    uint32_t	altitude;
    uint32_t	longitude;

    uint8_t     time[6];
    car_status_s    car_status;

} __attribute__((packed)) real_time_data;


typedef struct __warningtext {

    uint32_t	warning_id;
    uint8_t		start_flag;
    uint8_t		sound_type;
    uint8_t		forward_car_speed;
    uint8_t		forward_car_Distance;
    uint8_t		ldw_type;
    uint8_t		load_type;
    uint8_t		load_data;
    uint8_t		car_speed;
    uint16_t	high;
    uint32_t	altitude;
    uint32_t	longitude;
    uint8_t		time[6];
    car_status_s	car_status;	
    uint8_t		mm_num;
    sample_mm_info mm[0];


} __attribute__((packed)) warningtext;


#endif

typedef struct _file_trans_msg
{
    uint16_t    packet_num;
    uint16_t    packet_index;
} __attribute__((packed)) file_trans_msg;

typedef struct _sample_mm
{
    uint8_t     req_type;
    uint32_t    mm_id;
    uint16_t    packet_num;
    uint16_t    packet_idx;
} __attribute__((packed)) sample_mm;

int32_t sockfd = 0;
int32_t sample_escaple_msg(sample_prot_header *pHeader, int32_t msg_len);
uint8_t sample_calc_crc(sample_prot_header *pHeader, int32_t msg_len);

int32_t sample_assemble_msg(sample_prot_header *pHeader, uint8_t cmd, uint8_t *payload, int32_t payload_len);


uint32_t file_sum = 0;

uint32_t get_sum()
{
    uint32_t sum = 0;
    int i=0;
    int ret;
    
    FILE *fp;

    unsigned char readbuf[4096] = {0};

    fp = fopen(UPGRADE_FILE_PATH, "rb");
    if(!fp)
    {
        printf("open fail error!\n");
        return 0;
    }

    while(1)
    {
        ret = fread(readbuf, 1, 1024, fp);
        if(ret > 0)
        {
            for(i=0; i<ret; i++)
            {
                sum += readbuf[i];
            }
        }
        else
        {
            fclose(fp);
            file_sum = sum;
            printf("file sum:0x%08x\n", file_sum);
            return sum;
        }
    }

}


void printbuf(unsigned char *buf, int len)
{
    int i;

    for(i=0; i<len; i++)
    {
        if(i && (i%16 == 0))
            printf("\n");

        printf("0x%02x ", buf[i]);
    }

    printf("\n");
}

static const char * warning_to_str(sample_warning *w)
{
    static char buf[128];
    const char *st_str = NULL;
    const char *type_str = NULL;
    const char *sw_type_str[] = {
        "Und",
        "FCW",
        "LDW",
        "HW",
        "PCW",
        "FLC",
        "TSRW",
        "U_7", "U_8", "U_9", "U_A", "U_B", "U_C", "U_D", "U_E", "U_F"
            "TSR",
        "SNAP"};
    switch (w->status)
    {
        case SW_STATUS_BEGIN:   st_str = "Begin"; break;
        case SW_STATUS_END:     st_str = "End"; break;
        case SW_STATUS_EVENT:   st_str = "Event"; break;
        default:   st_str = "???"; break;
    }
    if (w->type <= SW_TYPE_SNAP) {
        type_str = sw_type_str[w->type];
    } else {
        type_str = "???";
    }
    snprintf(buf, sizeof(buf), "WARNING: st %-6s type %-6s mm %d",
            st_str, type_str, w->mm_count);
    if (w->mm_count > 0) {
        //parse mm info
    }

    return buf;
}

const char *sample_cm_str(uint8_t cmd)
{
    switch (cmd){
        case SAMPLE_CMD_QUERY:
            return "Query";
        case SAMPLE_CMD_FACTORY_RESET:
            return "Factory reset";
        case SAMPLE_CMD_SPEED_INFO:
            return "Speed Info";
        case SAMPLE_CMD_DEVICE_INFO:
            return "Device Info";
        case SAMPLE_CMD_UPGRADE:
            return "Upgrade";
        case SAMPLE_CMD_GET_PARAM:
            return "Get Param";
        case SAMPLE_CMD_SET_PARAM:
            return "Set Param";
        case SAMPLE_CMD_WARNING_REPORT:
            return "Warning report";
        case SAMPLE_CMD_REQ_MM_DATA:
            return "Req MM";
        case SAMPLE_CMD_UPLOAD_MM_DATA:
            return "Upload MM";
        case SAMPLE_CMD_SNAP_SHOT:
            return "SNAP SHOT";
        default:
            return "???";
    }
    return "???";
}





void print_para(para_setting *para)
{

printf("para->warning_speed_val       = %d\n", para->warning_speed_val);
printf("para->warning_volume          = %d\n", para->warning_volume);
printf("para->auto_photo_mode         = %d\n", para->auto_photo_mode);
printf("para->auto_photo_time_period  = %d\n", htons(para->auto_photo_time_period));
printf("para->auto_photo_distance_peri= %d\n", htons(para->auto_photo_distance_period));
printf("para->photo_num               = %d\n", para->photo_num);
printf("para->photo_time_period       = %d\n", para->photo_time_period);
printf("para->image_Resolution        = %d\n", para->image_Resolution);
printf("para->video_Resolution        = %d\n", para->video_Resolution);
//printf("para->reserve[9]);            = %d\n", para->reserve[9]);
printbuf(para->reserve, 9);
printf("para->obstacle_distance_thresh= %d\n", para->obstacle_distance_threshold);
printf("para->obstacle_video_time     = %d\n", para->obstacle_video_time);
printf("para->obstacle_photo_num      = %d\n", para->obstacle_photo_num);
printf("para->obstacle_photo_time_peri= %d\n", para->obstacle_photo_time_period);
printf("para->FLC_time_threshold      = %d\n", para->FLC_time_threshold);
printf("para->FLC_times_threshold     = %d\n", para->FLC_times_threshold);
printf("para->FLC_video_time          = %d\n", para->FLC_video_time);
printf("para->FLC_photo_num           = %d\n", para->FLC_photo_num);
printf("para->FLC_photo_time_period   = %d\n", para->FLC_photo_time_period);
printf("para->LDW_video_time          = %d\n", para->LDW_video_time);
printf("para->LDW_photo_num           = %d\n", para->LDW_photo_num);
printf("para->LDW_photo_time_period   = %d\n", para->LDW_photo_time_period);
printf("para->FCW_time_threshold      = %d\n", para->FCW_time_threshold);
printf("para->FCW_video_time          = %d\n", para->FCW_video_time);
printf("para->FCW_photo_num           = %d\n", para->FCW_photo_num);
printf("para->FCW_photo_time_period   = %d\n", para->FCW_photo_time_period);
printf("para->PCW_time_threshold      = %d\n", para->PCW_time_threshold);
printf("para->PCW_video_time          = %d\n", para->PCW_video_time);
printf("para->PCW_photo_num           = %d\n", para->PCW_photo_num);
printf("para->PCW_photo_time_period   = %d\n", para->PCW_photo_time_period);
printf("para->HW_time_threshold       = %d\n", para->HW_time_threshold);
printf("para->HW_video_time           = %d\n", para->HW_video_time);
printf("para->HW_photo_num            = %d\n", para->HW_photo_num);
printf("para->HW_photo_time_period    = %d\n", para->HW_photo_time_period);
printf("para->TSR_photo_num           = %d\n", para->TSR_photo_num);
printf("para->TSR_photo_time_period   = %d\n", para->TSR_photo_time_period);

}


void print_dsm_para(dsm_para_setting *para)
{
    printf("dsm_para->warning_speed_val             = %d\n", para->warning_speed_val);
    printf("dsm_para->warning_volume                = %d\n", para->warning_volume);
    printf("dsm_para->auto_photo_mode               = %d\n", para->auto_photo_mode);
    printf("dsm_para->auto_photo_time_period        = %d\n", para->auto_photo_time_period);
    printf("dsm_para->auto_photo_distance_period    = %d\n", para->auto_photo_distance_period);
    printf("dsm_para->photo_num                     = %d\n", para->photo_num);
    printf("dsm_para->photo_time_period             = %d\n", para->photo_time_period);
    printf("dsm_para->image_Resolution              = %d\n", para->image_Resolution);
    printf("dsm_para->video_Resolution              = %d\n", para->video_Resolution);
    printf("dsm_para->Smoke_TimeIntervalThreshold   = %d\n", para->Smoke_TimeIntervalThreshold);
    printf("dsm_para->Call_TimeIntervalThreshold    = %d\n", para->Call_TimeIntervalThreshold);
    printf("dsm_para->FatigueDriv_VideoTime         = %d\n", para->FatigueDriv_VideoTime);
    printf("dsm_para->FatigueDriv_PhotoNum          = %d\n", para->FatigueDriv_PhotoNum);
    printf("dsm_para->FatigueDriv_PhotoInterval     = %d\n", para->FatigueDriv_PhotoInterval);
    printf("dsm_para->FatigueDriv_resv              = %d\n", para->FatigueDriv_resv);
    printf("dsm_para->CallingDriv_VideoTime         = %d\n", para->CallingDriv_VideoTime);
    printf("dsm_para->CallingDriv_PhotoNum          = %d\n", para->CallingDriv_PhotoNum);
    printf("dsm_para->CallingDriv_PhotoInterval     = %d\n", para->CallingDriv_PhotoInterval);
    printf("dsm_para->SmokingDriv_VideoTime         = %d\n", para->SmokingDriv_VideoTime);
    printf("dsm_para->SmokingDriv_PhotoNum          = %d\n", para->SmokingDriv_PhotoNum);
    printf("dsm_para->SmokingDriv_PhotoInterval     = %d\n", para->SmokingDriv_PhotoInterval);

    printf("dsm_para->DistractionDriv_VideoTime        = %d\n", para->DistractionDriv_VideoTime);
    printf("dsm_para->DistractionDriv_PhotoNum         = %d\n", para->DistractionDriv_PhotoNum);
    printf("dsm_para->DistractionDriv_PhotoInterval    = %d\n", para->DistractionDriv_PhotoInterval);
    printf("dsm_para->AbnormalDriv_VideoTime     = %d\n", para->AbnormalDriv_VideoTime);
    printf("dsm_para->AbnormalDriv_PhotoNum      = %d\n", para->AbnormalDriv_PhotoNum);
    printf("dsm_para->AbnormalDriv_PhotoInterval = %d\n", para->AbnormalDriv_PhotoInterval);
}





void send_buf(uint8_t *buf, int len)
{
        printf("wrting buf len = %d...\n", len);
        //printbuf((uint8_t *)buf, len);
        write(sockfd, buf, len);//send cmd
}

int sendfile()
{
#define BUF_SIZE        (96*1024)
#define SEND_BUF_SIZE   (128*1024)
    int retval = 0;
    int ret;
    static uint32_t offset = 0;
    int msglen = 0;
    FILE *fp;
    static uint32_t packet_num = 0;
    static uint32_t packet_index = 0;
    uint8_t     message_id = 0x03;
    file_trans_msg file_trans;
    unsigned char *readbuf=NULL;
    unsigned char *txbuf=NULL;
    sample_prot_header * msg_out = NULL;

    fp = fopen(UPGRADE_FILE_PATH, "rb");
#define PACKAGE_LEN (64*1024)
//#define PACKAGE_LEN (1024)
    fseek(fp, 0, SEEK_SET);
    fseek(fp, 0, SEEK_END);

    //文件包序号从第一包开始.
    packet_num = (ftell(fp) + (PACKAGE_LEN-1))/PACKAGE_LEN + 1; //加上1包 是因为第一包是校验包，所以多出一包

    //printf("writing-[%d]/[%d] packet\n", packet_num, packet_index);

    readbuf = (unsigned char *)malloc(BUF_SIZE);
    if(!readbuf)
    {
        perror("malloc");
        retval = -1;
        goto out;
    }
    txbuf = (unsigned char *)malloc(SEND_BUF_SIZE);
    if(!txbuf)
    {
        perror("malloc");
        retval = -1;
        goto out;
    }
    
    msg_out = (sample_prot_header *) txbuf;
    printf("malloc ok!\n");

    if(packet_index == 0)
    {
        fclose(fp);
    

        readbuf[0] = message_id;
        file_trans.packet_num = htons(packet_num);
        file_trans.packet_index = htons(packet_index++);
        memcpy(&readbuf[1], &file_trans, sizeof(file_trans));
        readbuf[5] = (file_sum >> 24) & 0xff;
        readbuf[6] = (file_sum >> 16) & 0xff;
        readbuf[7] = (file_sum >> 8) & 0xff;
        readbuf[8] = (file_sum >> 0) & 0xff;

        printf("pre send first package ,sumcheck !\n");

        msglen = sample_assemble_msg(msg_out, SAMPLE_CMD_UPGRADE, readbuf, 4+1+4);
        send_buf((uint8_t *)msg_out, msglen);

        printf("send first package ,sumcheck !\n");
        retval = 0;
        goto out;

    }
    else
    {
        fseek(fp, PACKAGE_LEN*(packet_index-1), SEEK_SET);
        readbuf[0] = message_id;
        file_trans.packet_num = htons(packet_num);
        file_trans.packet_index = htons(packet_index++);
        memcpy(&readbuf[1], &file_trans, sizeof(file_trans));
        ret = fread(&readbuf[5], 1, PACKAGE_LEN, fp);
        fclose(fp);

        if(ret <=0)//send over
        {
            packet_index = 0;

            retval = -1;
            goto out;
        }
        else
        {
            printf("writing-[%d]/[%d] packet len:%d\n",packet_index, packet_num, ret);
            msglen = sample_assemble_msg(msg_out, SAMPLE_CMD_UPGRADE, readbuf, ret+1+4);
            send_buf((uint8_t *)msg_out, msglen);

            retval = 0;
            goto out;
        }
    }

out:
    if(readbuf)
        free(readbuf);
    if(txbuf)
        free(txbuf);

    return 0;
}

int32_t sample_jpg_fd = -1;
int debug_sample_msg(sample_prot_header * pHeader, int len)
{
    int i = 0;
    int pkglen = 0;
    uint8_t *barray = (uint8_t*) pHeader;
    sample_mm *mm = NULL;
    int sendlen;
    int msglen;
    static int warning_cnt = 0;
    int ret = 0;
    char filepath[50];
    static int fileindex = 0;
    sample_dev_info dev;
    uint8_t     message_id;
    uint8_t* pchar = NULL;
    unsigned char txbuf[4096] = {0};
    sample_prot_header * msg_out = (sample_prot_header *) txbuf;
    file_trans_msg recv_trans;

    unsigned char msgbuf[1024] = {0};
    warningtext *msg = (warningtext *)&msgbuf[0];

    static int sendcnt = 0;

    printf("%-20s:", "recv");
    printf("Magic 0x%02hhX Checksum 0x%02hhx Ver 0x%02hx Vid %02hx Did %02hhx CMD %02hhx (%-14s)\n",
            pHeader->magic, 
            pHeader->checksum, 
            htons(pHeader->version), 
            pHeader->vendor_id, 
            pHeader->device_id, 
            pHeader->cmd, sample_cm_str(pHeader->cmd));

    //printbuf((uint8_t *)pHeader, len);
#define MSG_CMD_TO_STRUT(TYPE, pHeader) ((TYPE) ((pHeader + 1)))
    if (SAMPLE_CMD_WARNING_REPORT == pHeader->cmd) {
   //     printf("%s\n", warning_to_str(MSG_CMD_TO_STRUT(sample_warning *, pHeader)));
            printbuf((uint8_t *)pHeader, len);

            //memcpy(msg, pHeader+1, sizeof(*msg));
            memcpy(msgbuf, pHeader+1, len-(sizeof(sample_prot_header) + 1));
            printf("sound_type = 0x%x\n", msg->sound_type);
            printf("warning_id = %d\n", htonl(msg->warning_id));
            printf("msg->mm_num = %d\n", msg->mm_num);
            for(i=0; i<msg->mm_num; i++)
            {
                printf("msg->mm.type = %d\n", msg->mm[i].type);
                printf("msg->mm.id = %d\n", htonl(msg->mm[i].id));
            }
#if 1
            //add send ack
            msglen =  sample_assemble_msg(pHeader, SAMPLE_CMD_WARNING_REPORT, NULL, 0);
            ret = write(sockfd, pHeader, msglen);//send ack
            printf("write ack ret = %d\n", ret);
#endif

    }

//  SAMPLE_CMD_QUERY            (0x2F)
//  SAMPLE_CMD_FACTORY_RESET    (0x30)
//  SAMPLE_CMD_SPEED_INFO       (0x31)
//  SAMPLE_CMD_DEVICE_INFO      (0x32)
//  SAMPLE_CMD_UPGRADE          (0x33)
//  SAMPLE_CMD_GET_PARAM        (0x34)
//  SAMPLE_CMD_SET_PARAM        (0x35)
//  SAMPLE_CMD_WARNING_REPORT   (0x36)
//  SAMPLE_CMD_REQ_MM_DATA      (0x50)
//  SAMPLE_CMD_UPLOAD_MM_DATA   (0x51)
//  SAMPLE_CMD_SNAP_SHOT        (0x52)
    if (SAMPLE_CMD_REQ_MM_DATA == pHeader->cmd \
            ) {
        printf("recv pHeader->cmd ack!\n");
        if(len == sizeof(sample_prot_header) + 1 )
        {
                printf("recv ack ok!\n");
        }
        else
            printf("recv cmd:0x%x, data len maybe error!\n", pHeader->cmd);
    }
    if (
            SAMPLE_CMD_QUERY == pHeader->cmd ||\
            SAMPLE_CMD_FACTORY_RESET == pHeader->cmd
            
            ) {
        printf("recv pHeader->cmd ack!\n");
        if(len == sizeof(sample_prot_header) + 1 )
        {
                printf("recv ack ok!\n");
        }
        else
            printf("recv cmd:0x%x, data len maybe error!\n", pHeader->cmd);
    }
    if (SAMPLE_CMD_GET_PARAM == pHeader->cmd) {

#if 1
        if(len == sizeof(sample_prot_header) + 1 + sizeof(dsm_para_setting))
        {
            print_dsm_para((dsm_para_setting *)(pHeader+1));
            memcpy(&par, pHeader+1, sizeof(par));
        }
        else
            printf("recv cmd:0x%x, data len maybe error!\n", pHeader->cmd);
#else

        if(len == sizeof(sample_prot_header) + 1 + sizeof(para_setting))
        {
            print_para((para_setting *)(pHeader+1));
            memcpy(&par, pHeader+1, sizeof(par));
        }
        else
            printf("recv cmd:0x%x, data len maybe error!\n", pHeader->cmd);
#endif
    }
    if (SAMPLE_CMD_DEVICE_INFO == pHeader->cmd) {
    
        if(len == sizeof(sample_prot_header) + 1 + sizeof(dev))
        {
            memcpy(&dev, pHeader+1, sizeof(dev));
            printf("len:%d\n", dev.vendor_name_len);
            printf("name:%s\n", dev.vendor_name);
            printf("len:%d\n", dev.prod_code_len);
            printf("name:%s\n", dev.prod_code);
            printf("len:%d\n", dev.hw_ver_len);
            printf("name:%s\n", dev.hw_ver);
            printf("len:%d\n", dev.sw_ver_len);
            printf("name:%s\n", dev.sw_ver);
            printf("len:%d\n", dev.dev_id_len);
            printf("name:%s\n", dev.dev_id);
            printf("len:%d\n", dev.custom_code_len);
            printf("name:%s\n", dev.custom_code);
        }
        else
            printf("recv cmd:0x%x, data len maybe error!\n", pHeader->cmd);
    }
//#define SAMPLE_CMD_REQ_STATUS       (0x37)
//#define SAMPLE_CMD_UPLOAD_STATUS    (0x38)
    if (SAMPLE_CMD_REQ_STATUS == pHeader->cmd) {
    
        if(len == sizeof(sample_prot_header) + 1 + 5)
        {
            printf("recv work status!\n");
        }
        else
            printf("recv cmd:0x%x, data len maybe error!\n", pHeader->cmd);
    
    
    }
    if (SAMPLE_CMD_UPLOAD_STATUS == pHeader->cmd) {
            //add send ack
            msglen =  sample_assemble_msg(pHeader, SAMPLE_CMD_UPLOAD_STATUS, NULL, 0);
            ret = write(sockfd, pHeader, msglen);//send ack
            printf("send workstatus ack ret = %d\n", ret);
    
    }
    if (SAMPLE_CMD_SNAP_SHOT == pHeader->cmd || \
            SAMPLE_CMD_SET_PARAM == pHeader->cmd
            ) {
    
        if(len == sizeof(sample_prot_header) + 1 + 1)
        {
            if(*(uint8_t *)(pHeader+1) == 0)
                printf("recv ack!\n");
            else
                printf("recv ack err!\n");
        }
        else
            printf("recv cmd:0x%x, data len maybe error!\n", pHeader->cmd);
    
    }
    if (SAMPLE_CMD_UPLOAD_MM_DATA == pHeader->cmd) {
        mm = (sample_mm *) (pHeader + 1);

        printf("MM#0x%04x %03d/%03d\n", mm->mm_id, htons(mm->packet_idx), htons(mm->packet_num));
        pkglen = len - sizeof(sample_mm) - sizeof(sample_prot_header) -1;
        printf("recv pkg len = %d", pkglen);


        if (0 == htons(mm->packet_idx)) {
            //sprintf(filepath, "./jpeg/sample-%d.jpg", fileindex++);
            sprintf(filepath, "./jpeg/mm-%d.%s", htonl(mm->mm_id), mm->req_type == 0 ? "jpg":"avi");
            sample_jpg_fd = open(filepath, O_RDWR|O_CREAT, 0644);
            if (sample_jpg_fd < 0) {
                printf("Open failed\n");
                exit(-1);
            }
        }
        //write(sample_jpg_fd, (mm + 1), 1024);
        write(sample_jpg_fd, (mm + 1), pkglen);
        if (htons(mm->packet_idx) + 1 == htons(mm->packet_num)) {
            printf("write file over!\n");
            close(sample_jpg_fd);

          //  sem_post(&sem);
        }


        /*********************send ack*********************************/
        pchar = (uint8_t *)pHeader;
        pHeader->cmd = SAMPLE_CMD_UPLOAD_MM_DATA;
        //    pHeader->version = 0x7E; //test
        //   pHeader->vendor_id = 0x7d; //test
        sendlen = sizeof(sample_prot_header) + sizeof(sample_mm);
        //	printf("header = %d, mm = %d\n" ,sizeof(sample_prot_header), sizeof(sample_mm));

        pchar[sendlen] = 0; //success
        pchar[sendlen+1] = SAMPLE_PROT_MAGIC;
        sendlen += 2;
        pHeader->checksum = sample_calc_crc(pHeader, sendlen);
        sendlen = sample_escaple_msg(pHeader, sendlen);

        if(0)//test repeat
        {
            if(htons(mm->packet_idx) == 20)
                return 0;
        }

        printf("send ack cnt = %d\n", sendcnt++);
        printbuf((uint8_t *)pHeader, sendlen);
        write(sockfd, pHeader, sendlen);//send ack

        return 0;

    }

    if (SAMPLE_CMD_UPGRADE == pHeader->cmd) {
        
        message_id = *(uint8_t *)(pHeader + 1);
        if(message_id == 0x01)
        {
            printf("recv upgrade start cmd ack!\n");
            message_id = 0x02;
            msglen = sample_assemble_msg(msg_out, SAMPLE_CMD_UPGRADE, (uint8_t *)&message_id, 1);
            send_buf((uint8_t *)msg_out, msglen);
            return 0;
        }
        else if(message_id == 0x02)
        {
            printf("recv upgrade clean cmd ack!\n");
            sendfile();
        }
        else if(message_id == 0x03)
        {
            printf("recv upgrade start trans cmd ack!\n");
            
            pchar = (uint8_t *)(pHeader + 1);
            memcpy(&recv_trans, pchar+1, sizeof(recv_trans));
            printf("trans file index = %d/%d\n", htons(recv_trans.packet_index), htons(recv_trans.packet_num));

            //收到最后一包不再发送。
            if(htons(recv_trans.packet_num) == 1 + htons(recv_trans.packet_index))
            {
                printf("send the last  upgrade cmd !\n");
                message_id = 0x04;
                msglen = sample_assemble_msg(msg_out, SAMPLE_CMD_UPGRADE, (uint8_t *)&message_id, 1);
                send_buf((uint8_t *)msg_out, msglen);
            }
            else
                sendfile();
        }
        else if(message_id == 0x04)
        {
            printf("recv new app start ack!\n");
        }
        else
        {
            printf("recv upgrade err!\n");
        }
        
        return 0;

    }

}

uint8_t sample_calc_crc(sample_prot_header *pHeader, int32_t msg_len)
{
    int32_t i = 0;
    uint32_t chksum = 0;
    uint8_t * start = (uint8_t *) &pHeader->vendor_id;

#define NON_CRC_LEN (2 * sizeof(pHeader->magic) /*head and tail*/ + \
        sizeof(pHeader->version) + \
        sizeof(pHeader->checksum))

    for (i = 0; i < msg_len - NON_CRC_LEN; i++) {
        chksum += start[i];

#ifdef DEBUG_CRC
        printf("#%04d 0x%02hhx = 0x%08x\n", i, start[i], chksum);
#endif
    }
    return (uint8_t) (chksum & 0xFF);
}

int32_t sample_escaple_msg(sample_prot_header *pHeader, int32_t msg_len)
{
    int32_t i = 0;
    int32_t escaped_len = msg_len;
    uint8_t *barray = (uint8_t*) pHeader;
#ifdef DEBUG_ESCAPING
    for (i = 0; i < msg_len; i++) {
        printf("0x%02hhx ", barray[i]);
    }
    printf("\n");
#endif
    //ignore head/tail magic
    for (i = 1; i < escaped_len - 1; i++) {
#ifdef DEBUG_ESCAPING
        printf("0x%02hhx\n", barray[i]);
#endif
        if (SAMPLE_PROT_MAGIC == barray[i]) {
            memmove(&barray[i+1], &barray[i], escaped_len - i);
            barray[i]   = SAMPLE_PROT_ESC_CHAR;
            barray[i+1] = 0x2;
            i++;
            escaped_len ++;
        } else if (SAMPLE_PROT_ESC_CHAR == barray[i]) {
            memmove(&barray[i+1], &barray[i], escaped_len - i);
            barray[i]   = SAMPLE_PROT_ESC_CHAR;
            barray[i+1] = 0x1;
            i++;
            escaped_len ++;
        }
    }
#ifdef DEBUG_ESCAPING
    for (i = 0; i < escaped_len; i++) {
        printf("0x%02hhx ", barray[i]);
    }
    printf("\n");
#endif
    return escaped_len;
}

int32_t sample_unescaple_msg(sample_prot_header *pHeader, int32_t escaped_len)
{
    int32_t i = 0;
    int32_t msg_len = escaped_len;
    uint8_t *barray = (uint8_t*) pHeader;
#ifdef DEBUG_UN_ESCAPING
    for (i = 0; i < escaped_len; i++) {
        printf("0x%02hhx ", barray[i]);
    }
    printf("\n");
#endif
    if (SAMPLE_PROT_MAGIC != barray[0] || SAMPLE_PROT_MAGIC != barray[escaped_len - 1]) {
        return 0;
    }
    //ignore head magic /char before tail magic
    for (i = 1; i < escaped_len - 2; i++) {
#ifdef DEBUG_UN_ESCAPING
        printf("0x%02hhx\n", barray[i]);
#endif
        if (SAMPLE_PROT_ESC_CHAR == barray[i] && (0x1 == barray[i+1] || 0x2 == barray[i+1])) {
            barray[i+1]   = SAMPLE_PROT_ESC_CHAR + (barray[i+1] - 1);
            memmove(&barray[i], &barray[i + 1], escaped_len - i);
            msg_len --; 
        }
    }
#ifdef DEBUG_UN_ESCAPING
    for (i = 0; i < msg_len; i++) {
        printf("0x%02hhx ", barray[i]);
    }
    printf("\n");
#endif
    return msg_len;
}

int32_t sample_assemble_msg(sample_prot_header *pHeader, uint8_t cmd,
        uint8_t *payload, int32_t payload_len)
{
    int32_t msg_len = sizeof(*pHeader) + 1 + payload_len;
    uint8_t *data = ((uint8_t*) pHeader + sizeof(*pHeader));
    uint8_t *tail = data + payload_len;

    memset(pHeader, 0, sizeof(*pHeader));
    pHeader->magic = SAMPLE_PROT_MAGIC;
    //  pHeader->version  = 0x1;
    pHeader->version  = SAMPLE_PROT_MAGIC;

    pHeader->vendor_id= htons(0x5678);
    //pHeader->device_id= SAMPLE_DEVICE_ID_ADAS;
    pHeader->device_id= SAMPLE_DEVICE_ID_DSM;
    pHeader->cmd = cmd;
    if (payload_len > 0) {
        memcpy(data, payload, payload_len);
    }
    tail[0] = SAMPLE_PROT_MAGIC;

    pHeader->checksum = sample_calc_crc(pHeader, msg_len);

    msg_len = sample_escaple_msg(pHeader, msg_len);

    return msg_len;
}


static int socket_to_host_init(void)
{
#define SERVER_PORT (8888)
    int s = -1;
    int enable = 1;
    int32_t ret = 0;
    //    const char *server_ip = "192.168.100.100";
    const char *server_ip = "0.0.0.0";
    struct sockaddr_in minit_serv_addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("Create socket failed %s\n", strerror(errno));
        exit(1);
    }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    memset(&minit_serv_addr, 0, sizeof(minit_serv_addr));
    minit_serv_addr.sin_family = AF_INET;
    minit_serv_addr.sin_port   = htons(SERVER_PORT);

    //	minit_serv_addr.sin_addr.s_addr = INADDR_ANY;
#if 1
    ret = inet_aton(server_ip, &minit_serv_addr.sin_addr);
    if (0 == ret) {
        printf("inet_aton failed %d %s\n", ret, strerror(errno));
        exit(1);
    }
#endif
    ret = bind(s, (struct sockaddr *) &minit_serv_addr, sizeof(minit_serv_addr));
    if (0 != ret) {
        printf("bind failed %d %s\n", ret, strerror(errno));
        exit(2);
    }

    ret = listen(s, 1);
    if (0 != ret) {
        printf("listen failed %d %s\n", ret, strerror(errno));
        exit(3);
    }
    return s;
}


static int sock_connect(void)
{
#define DATA_COLLECTOR_CMD_PORT (2017)
    int s = -1;
    int enable = 1;
    int32_t ret = 0;
    //    const char *server_ip = "127.0.0.1";
    const char *server_ip = "192.168.2.100";
    struct sockaddr_in minit_serv_addr;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        printf("Create socket failed %s\n", strerror(errno));
        exit(1);
    }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));

    memset(&minit_serv_addr, 0, sizeof(minit_serv_addr));
    minit_serv_addr.sin_family = AF_INET;
    minit_serv_addr.sin_port   = htons(DATA_COLLECTOR_CMD_PORT);

    ret = inet_aton(server_ip, &minit_serv_addr.sin_addr);
    if (0 == ret) {
        printf("inet_aton failed %d %s\n", ret, strerror(errno));
        exit(1);
    }


    if( 0 == connect(s, (struct sockaddr *)&minit_serv_addr, sizeof(minit_serv_addr)))
    {
        printf("connect ok!\n");
    }

    /*
       ret = bind(s, (struct sockaddr *) &minit_serv_addr, sizeof(minit_serv_addr));
       if (0 != ret) {
       printf("bind failed %d %s\n", ret, strerror(errno));
       exit(2);
       }

       ret = listen(s, 1);
       if (0 != ret) {
       printf("listen failed %d %s\n", ret, strerror(errno));
       exit(3);
       }
       */
    return s;
}

void *pthread_recv(void *para)
{
    int32_t ret = 0;
    struct sockaddr_in in_sa;
    uint32_t in_sa_len = 0;
    uint8_t readbuf[96*1024];
    int i=0;
    int rawcnt=0;


#if 0
    uint8_t data[] = {
        0x7e, 0x66, 0x00, 0x01, 0x12, 0x34, 0x64, 0x36, 0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 
        0x00, 0x28, 0x41, 0xc5, 0x7f, 0x00, 0x00, 0x00, 0x80, 0x0d, 0xb0, 0xb6, 0x7f, 0x00, 0x75, 0x06, 
        0x12, 0x09, 0x1c, 0x2b, 0x7f, 0x00, 0x00, 0x00, 0x90, 0x0d, 0xb0, 0xb6, 0x7e, 0x7e, 0x67, 0x00, 
        0x01, 0x12, 0x34, 0x64, 0x36, 0x00, 0x06, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x28, 0x41, 
        0xc5, 0x7f, 0x00, 0x00, 0x00, 0x80, 0x0d, 0xb0, 0xb6, 0x7f, 0x00, 0x75, 0x06, 0x12, 0x09, 0x1c, 
        0x2b, 0x7f, 0x00, 0x00, 0x00, 0x90, 0x0d, 0xb0, 0xb6, 0x7e
    };




    while(sizeof(data) != i)
    {
        //recv host cmd, push to queue
        if(!isBufferFull(myBuffer_ptr))
        {
            bufferWrite(myBuffer_ptr, data[i++]);
        }
        else
        {
            usleep(20);
            printf("cir buf flow\n");
        }
    }

#endif


    int32_t cmd_sock = socket_to_host_init();
    if (cmd_sock < 0) {
        return NULL;
    }

    while(1)
    {
        printf("waiting client connect..\n");
        sockfd = accept(cmd_sock, (struct sockaddr *) &in_sa, &in_sa_len);
        if (sockfd < 0) {
            printf("accept failed %d %s\n", ret, strerror(errno));
            exit(4);
        }
        else
        {
            printf("client connect ok\n");
        }

        while (1) {
            memset(readbuf, 0, sizeof(readbuf));
            ret = read(sockfd, readbuf, sizeof(readbuf));
            if (ret <= 0) {
                printf("read failed %d %s\n", ret, strerror(errno));
                close(sockfd);
                sockfd = -1;
                break;
            }
            else//write to buf
            {
                //printf("recv raw[%d], len=%d:\n",rawcnt++, ret);
            //    printbuf(readbuf, ret);
           //     printf("----------------raw-----------------\n");
                i=0;
                while(ret != i)
                {
                    //recv host cmd, push to queue
                    if(!isBufferFull(myBuffer_ptr))
                    {
                        bufferWrite(myBuffer_ptr, readbuf[i++]);
                    }
                    else
                    {
                        usleep(20);
                        printf("cir buf flow\n");
                    }
                }
                //		printf("push over!\n");
            }
        }
    }
    printf("close socket!\n");
    close(sockfd);

    return NULL;
}

void *pthread_recv_deal(void *para)
{
    unsigned char ch, crc;
    char start = 0;
    char flag = 0;
    unsigned char readbuf[96*1024];
    sample_prot_header *pHeader = (sample_prot_header *) readbuf;
    int cnt=0;
    int framelen = 0;
    int framecnt=0;

    while(1)
    {
        //read
        if(!isBufferEmpty(myBuffer_ptr))
        {
            bufferRead(myBuffer_ptr,ch);
        //    printf("0x%x ", ch);
            if(!start && (ch == SAMPLE_PROT_MAGIC) && (cnt == 0))//get head
            {
                readbuf[cnt] = SAMPLE_PROT_MAGIC;
                cnt++;
                start = 1;
                continue;
            }
            else if(start && (ch == SAMPLE_PROT_MAGIC) && (cnt > 0))//get tail
            {
                if(cnt < 6)//maybe error frame, as head, restart
                {
                    cnt = 0;
                    readbuf[cnt] = SAMPLE_PROT_MAGIC;
                    cnt++;
                    start = 1;
                    printf("error:\n");
                    continue;
                }

                //get tail
                readbuf[cnt] = SAMPLE_PROT_MAGIC;
                start = 0;//over
                framelen = cnt + 1;
                cnt = 0;

                if(framelen >0)
                {
                  //  printf("get a framelen = %d, cnt=%d\n", framelen, framecnt++);
                 //   printbuf(readbuf, framelen);
                 //   printf("----------------frame over-----------------\n");

                    crc = sample_calc_crc(pHeader, framelen);
                    if (crc != pHeader->checksum) {
                        printf("Checksum missmatch calcated: 0x%02hhx != 0x%2hhx\n",
                                crc, pHeader->checksum);
                    }
                    else
                    {
                        debug_sample_msg(pHeader, framelen);
                    }

                    framelen = 0;
                }
                continue;
            }
            else if(!start)//error data
            {
                continue;
            }
            else
            {
                if((ch == SAMPLE_PROT_ESC_CHAR) && !flag)//need deal
                {
                    flag = 1;
                    readbuf[cnt] = ch;
                }
                else if(flag && (ch == 0x02))
                {
                    readbuf[cnt] = SAMPLE_PROT_MAGIC;
                    cnt++;
                    flag = 0;
                }
                else if(flag && (ch == 0x01))
                {
                    readbuf[cnt] = SAMPLE_PROT_ESC_CHAR;
                    cnt++;
                    flag = 0;
                }
                else if(flag && (ch != 0x01) && (ch != 0x02))
                {
                    cnt++;
                    readbuf[cnt] = ch;
                    cnt++;
                    flag = 0;
                }
                else
                {
                    readbuf[cnt] = ch;
                    cnt++;
                }

            }

        }
        else
        {
            usleep(20);
        }

    }
}

int main(int argc, const char *argv[])
{
    real_time_data rt_data;
    int i;
    int bufsize = 96*1024;
    uint32_t mm_id = 0;
    uint8_t message_id = 0x01;
    int32_t cmd_idx = 0;
    int32_t msg_out_len = 0;
    uint8_t test_cmds[] = {
        SAMPLE_CMD_QUERY, 
        SAMPLE_CMD_FACTORY_RESET,//1
        SAMPLE_CMD_SPEED_INFO,//no need ack
        SAMPLE_CMD_DEVICE_INFO,//3
        SAMPLE_CMD_UPGRADE,//4
        SAMPLE_CMD_GET_PARAM,
        SAMPLE_CMD_SET_PARAM,//6
        SAMPLE_CMD_GET_PARAM,

        SAMPLE_CMD_WARNING_REPORT,

        SAMPLE_CMD_REQ_STATUS, //9
        SAMPLE_CMD_UPLOAD_STATUS,

        SAMPLE_CMD_REQ_MM_DATA,//11
        SAMPLE_CMD_UPLOAD_MM_DATA,
        SAMPLE_CMD_SNAP_SHOT
    };
    //uint8_t test_cmds[] = {SAMPLE_CMD_REQ_MM_DATA};
    unsigned char txbuf[4096] = {0};
    sample_prot_header * msg_out = (sample_prot_header *) txbuf;
    uint8_t type=0;

    pthread_t pth[5];
    sample_mm_info mm;

    sem_init(&sem, 0, 0);

    get_sum();

    bufferInit(myBuffer, bufsize, unsigned char);
    myBuffer_ptr = &myBuffer;

    pthread_create(&pth[0], NULL, pthread_recv, NULL);
    pthread_create(&pth[1], NULL, pthread_recv_deal, NULL);

//sleep(5);

//    sem_post(&sem);
    memset(&rt_data, 0, sizeof(rt_data));
    while(1)
    {
        printf("waiting\n");
//        sem_wait(&sem);
        
        printf("input your cmd(input 100 for help):\n");
        scanf("%d", &cmd_idx);
        getchar();

        if(cmd_idx == 100)
        {
            printf("cmd list:\n");
            printf("0: SAMPLE_CMD_QUERY\n"); 
            printf("1: SAMPLE_CMD_FACTORY_RESET\n");
            printf("2: SAMPLE_CMD_SPEED_INFO\n");
            printf("3: SAMPLE_CMD_DEVICE_INFO\n");
            printf("4: SAMPLE_CMD_UPGRADE\n");
            printf("5: SAMPLE_CMD_GET_PARAM\n");
            printf("6: SAMPLE_CMD_SET_PARAM\n");
            printf("7: SAMPLE_CMD_GET_PARAM\n");
            printf("8: SAMPLE_CMD_WARNING_REPORT\n");
            printf("9: SAMPLE_CMD_REQ_STATUS\n");
            printf("10: SAMPLE_CMD_UPLOAD_STATUS\n");
            printf("11: SAMPLE_CMD_REQ_MM_DATA\n");
            printf("12: SAMPLE_CMD_UPLOAD_MM_DATA\n");
            printf("13: SAMPLE_CMD_SNAP_SHOT\n");

            continue;
        }

        if(test_cmds[cmd_idx] == SAMPLE_CMD_REQ_MM_DATA)
        {

            printf("input req mm type:\n");
            scanf("%c", &type);
            getchar();

            printf("input req mm id:\n");
            scanf("%d", &mm_id);
            getchar();
        }
        memset(txbuf, 0, sizeof(txbuf));
        mm.type = type - '0';
        printf("cmd = %d, mm_type = %d, mm_id = %d\n", cmd_idx, mm.type, mm_id);
        mm.id = htonl(mm_id);
       // msg_out_len = sample_assemble_msg(msg_out, test_cmds[cmd_idx], (uint8_t *)&mm, sizeof(mm));//encode
       // msg_out_len = sample_assemble_msg(msg_out, 0x52, NULL, 0);//encode

        if(test_cmds[cmd_idx] == SAMPLE_CMD_SET_PARAM){
            memset(&par, 0xFF, sizeof(par));
            par.video_Resolution = 6;
            par.image_Resolution = 6;
            //par.warning_speed_val = 60;
            //par.auto_photo_time_period = htons(1800);
#if 0
            par.warning_speed_val = 30;
            par.HW_photo_num = 3;
            par.auto_photo_mode = 2;
            par.auto_photo_time_period = htons(20);
#endif
            msg_out_len = sample_assemble_msg(msg_out, test_cmds[cmd_idx], (uint8_t *)&par, sizeof(par));//encode
        }
        else if(test_cmds[cmd_idx] == SAMPLE_CMD_REQ_MM_DATA){
            msg_out_len = sample_assemble_msg(msg_out, test_cmds[cmd_idx], (uint8_t *)&mm, sizeof(mm));//encode
        }
        else if(test_cmds[cmd_idx] == SAMPLE_CMD_UPGRADE){
            msg_out_len = sample_assemble_msg(msg_out, test_cmds[cmd_idx], (uint8_t *)&message_id, sizeof(message_id));//encode
        }
        else if(test_cmds[cmd_idx] == SAMPLE_CMD_SPEED_INFO){
            rt_data.car_speed = 80;
            rt_data.mileage += 1; 
            msg_out_len = sample_assemble_msg(msg_out, test_cmds[cmd_idx], (uint8_t *)&rt_data, sizeof(rt_data));//encode
        }
        else
            msg_out_len = sample_assemble_msg(msg_out, test_cmds[cmd_idx], NULL, 0);//encode

        printf("--------------------send cmd 0x%x:\n", test_cmds[cmd_idx]);
        printbuf((uint8_t *)msg_out, msg_out_len);
        write(sockfd, msg_out, msg_out_len);//send cmd
 //       write(sockfd, msg_out, msg_out_len);//send cmd
        cmd_idx = (++cmd_idx) % 12;
    }

    pthread_join(pth[0], NULL);

    close(sockfd);
    return 0;
}

