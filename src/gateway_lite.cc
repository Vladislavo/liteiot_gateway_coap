#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h> //inet_addr
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/time.h>
#include <libpq-fe.h>
#include <math.h>
#include <signal.h>
#include <time.h>

#include <errno.h>

#include "gateway_protocol.h"
#include "gateway_telemetry_protocol.h"
#include "base64.h"
#include "task_queue.h"
#include "json.h"
#include "aes.h"
#include "gw_stat_linked_list.h"


#define TIMEDATE_LENGTH			32
#define PEND_SEND_RETRIES_MAX		5
#define GATEWAY_PROTOCOL_APP_KEY_SIZE	8
#define DEVICE_DATA_MAX_LENGTH		256
#define GATEWAY_SECURE_KEY_SIZE		16
#define GATEWAY_ID_SIZE			6


typedef struct {
	char 		db_addr[15+1];
	uint16_t 	db_port;
	char 		db_name[32];
	char 		db_user_name[32];
	char 		db_user_pass[32];
	uint32_t	telemetry_send_period;
} dynamic_conf_t;

typedef struct {
	uint8_t 	gw_id[GATEWAY_ID_SIZE];
	uint8_t 	gw_secure_key[GATEWAY_SECURE_KEY_SIZE];
	uint16_t 	gw_port;
	char 		db_type[20];
	char 		platform_gw_manager_ip[20];
	uint16_t 	platform_gw_manager_port;
	uint8_t 	thread_pool_size;
} static_conf_t;

typedef struct {
	static_conf_t  static_conf;
	dynamic_conf_t dynamic_conf;
} gw_conf_t;

typedef struct {
	uint32_t utc;
	char timedate[TIMEDATE_LENGTH];

	uint8_t data[DEVICE_DATA_MAX_LENGTH];
	uint8_t data_length;
} sensor_data_t;

typedef struct {
	gateway_protocol_conf_t gwp_conf;
	int server_desc;
	int client_desc;
	struct sockaddr_in server;
	struct sockaddr_in client;
	unsigned int sock_len;
} gcom_ch_t; // gateway communication channel

typedef struct {
	gcom_ch_t gch;	
	gateway_protocol_packet_type_t packet_type;
	uint8_t packet[DEVICE_DATA_MAX_LENGTH];
	uint8_t packet_length;
} gcom_ch_request_t;

typedef struct {
	uint64_t errors_count;
} gw_stat_t;

static const char * static_conf_file  = "conf/static.conf";
static const char * dynamic_conf_file = "conf/dynamic.conf";
static int read_static_conf (const char *static_conf_file_path,  gw_conf_t *gw_conf);
static int read_dynamic_conf(const char *dynamic_conf_file_path, gw_conf_t *gw_conf);
static void process_static_conf (json_value* value, static_conf_t  *static_conf);
static void process_dynamic_conf(json_value* value, dynamic_conf_t *dynamic_conf);
static json_value * read_json_conf(const char *file_path);

void process_packet(void *request);

uint8_t gateway_auth(const gw_conf_t *gw_conf, const char *dynamic_conf_file_path);
void	*gateway_mngr(void *gw_conf);

int send_gcom_ch(gcom_ch_t *gch, uint8_t *pck, uint8_t pck_size);
int recv_gcom_ch(gcom_ch_t *gch, uint8_t *pck, uint8_t *pck_length, uint16_t pck_size);

void gateway_protocol_data_send_payload_decode(
	sensor_data_t *sensor_data, 
	const uint8_t *payload, 
	const uint8_t payload_length);

void gateway_protocol_mk_stat(
	gcom_ch_t *gch,
	gateway_protocol_stat_t stat,
	uint8_t *pck,
	uint8_t *pck_len);

void send_utc(gcom_ch_t *pch);

void gateway_protocol_checkup_callback(gateway_protocol_conf_t *gwp_conf);

void ctrc_handler (int sig);
static volatile uint8_t working = 1;

pthread_mutex_t mutex;
pthread_mutex_t gw_stat_mutex;
PGconn *conn;

gw_stat_t gw_stat;

int main (int argc, char **argv) {
	gw_conf_t *gw_conf = (gw_conf_t *)malloc(sizeof(gw_conf_t));
	char *db_conninfo = (char *)malloc(512);
	gcom_ch_t gch;
	task_queue_t *tq;
	pthread_t gw_mngr;
	sigset_t sigset;
	
	gw_stat.errors_count = 0;

	sigemptyset(&sigset);
	/* block SIGALRM for gateway manager thread */
	sigaddset(&sigset, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	signal(SIGINT, ctrc_handler);
	
	if (read_static_conf(static_conf_file, gw_conf)) {
		return EXIT_FAILURE;
	}

	gateway_telemetry_protocol_init(gw_conf->static_conf.gw_id, gw_conf->static_conf.gw_secure_key);

	if (!gateway_auth(gw_conf, dynamic_conf_file)) {
		fprintf(stderr, "Gateway authentication failure.");
		return EXIT_FAILURE;
	}

	if (read_dynamic_conf(dynamic_conf_file, gw_conf)) {
		fprintf(stderr, "Read dynamic configuration failure.");
		return EXIT_FAILURE;
	}
	
	snprintf(db_conninfo, 512, 
			"hostaddr=%s port=%d dbname=%s user=%s password=%s", 
			gw_conf->dynamic_conf.db_addr,
			gw_conf->dynamic_conf.db_port,
			gw_conf->dynamic_conf.db_name,
			gw_conf->dynamic_conf.db_user_name,
			gw_conf->dynamic_conf.db_user_pass);
	
	printf("db_conf : '%s'\n", db_conninfo);

	conn = PQconnectdb(db_conninfo);
	
	snprintf(db_conninfo, 512, 
			"id=%s secure_key=%s port=%d type=%s thread_pool_size=%d telemetry_send_period=%d\n", 
			gw_conf->static_conf.gw_id,
			gw_conf->static_conf.gw_secure_key,
			gw_conf->static_conf.gw_port,
			gw_conf->static_conf.db_type,
			gw_conf->static_conf.thread_pool_size,
			gw_conf->dynamic_conf.telemetry_send_period);
	printf("gw_conf : '%s'\n", db_conninfo);
	free(db_conninfo);

	if (PQstatus(conn) == CONNECTION_BAD) {
		fprintf(stderr,"connection to db error: %s\n", PQerrorMessage(conn));
		free(gw_conf);
		return EXIT_FAILURE;
	}

	if ((gch.server_desc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket creation error");
		free(gw_conf);
		return EXIT_FAILURE;
	}

	gch.server.sin_family 		= AF_INET;
	gch.server.sin_port		= htons(gw_conf->static_conf.gw_port);
	gch.server.sin_addr.s_addr 	= htonl(INADDR_ANY);

	if (bind(gch.server_desc, (struct sockaddr *) &gch.server, sizeof(gch.server)) < 0) {
		perror("binding error");
		free(gw_conf);
		return EXIT_FAILURE;
	}
	
	if (listen(gch.server_desc, gw_conf->static_conf.thread_pool_size) < 0) {
		perror("listen error");
		free(gw_conf);
		close(gch.server_desc);
		return EXIT_FAILURE;
	}

	if (pthread_create(&gw_mngr, NULL, gateway_mngr, gw_conf)) {
		fprintf(stderr, "Failed to create gateway manager thread.");
		free(gw_conf);
		close(gch.server_desc);
		return EXIT_FAILURE;
	}

	if(!(tq = task_queue_create(gw_conf->static_conf.thread_pool_size))) {
		perror("task_queue creation error");
		free(gw_conf);
		close(gch.server_desc);
		return EXIT_FAILURE;
	}

	pthread_mutex_init(&mutex, NULL);
	pthread_mutex_init(&gw_stat_mutex, NULL);

	gateway_protocol_set_checkup_callback(gateway_protocol_checkup_callback);

	gw_stat_linked_list_init();

	while (working) {
		printf("listenninig...\n");
		
		gcom_ch_request_t *req = (gcom_ch_request_t *)malloc(sizeof(gcom_ch_request_t));
		memset(req, 0x0, sizeof(gcom_ch_request_t));
		memcpy(&req->gch, &gch, sizeof(gcom_ch_t));

		req->gch.sock_len = sizeof(req->gch.client);
		
		if (recv_gcom_ch(&req->gch, req->packet, &req->packet_length, DEVICE_DATA_MAX_LENGTH)) {
			task_queue_enqueue(tq, process_packet, req);
		} else {
			fprintf(stderr, "packet receive error\n");
		}
	}

	free(gw_conf);
	pthread_mutex_destroy(&mutex);
	close(gch.server_desc);
	PQfinish(conn);

	return EXIT_SUCCESS;
}

void ctrc_handler (int sig) {
	working = 0;
}

void process_packet(void *request) {
	gcom_ch_request_t *req = (gcom_ch_request_t *)request;
	uint8_t payload[DEVICE_DATA_MAX_LENGTH];
	uint8_t payload_length;	
	PGresult *res;

	if (gateway_protocol_packet_decode(
		&(req->gch.gwp_conf),
		&(req->packet_type),
		&payload_length, payload,
		req->packet_length, req->packet))
	{
		if (req->packet_type == GATEWAY_PROTOCOL_PACKET_TYPE_TIME_REQ) {
			printf("TIME REQ received\n");
			send_utc(&(req->gch));
		} else if (req->packet_type == GATEWAY_PROTOCOL_PACKET_TYPE_DATA_SEND) {
			sensor_data_t sensor_data;
			time_t t;
			// DEVICE_DATA_MAX_LENGTH*2 {hex} + 150
			char db_query[662];

			printf("DATA SEND received\n");
			gateway_protocol_data_send_payload_decode(&sensor_data, payload, payload_length);
			
			if (sensor_data.utc == 0) {
				struct timeval tv;
				gettimeofday(&tv, NULL);
				t = tv.tv_sec;
			} else {
				t = sensor_data.utc;
			}
			
			strftime(sensor_data.timedate, TIMEDATE_LENGTH, "%d/%m/%Y %H:%M:%S", localtime(&t));
			snprintf(db_query, sizeof(db_query), 
				"INSERT INTO dev_%s_%d VALUES (%lu, '%s', $1)", 
				(char *)req->gch.gwp_conf.app_key, req->gch.gwp_conf.dev_id, t, sensor_data.timedate
			);
			
			const char *params[1];
			int paramslen[1];
			int paramsfor[1];
			params[0] = (char *) sensor_data.data;
			paramslen[0] = sensor_data.data_length;
			paramsfor[0] = 1; // format - binary

			pthread_mutex_lock(&gw_stat_mutex);
			gw_stat_linked_list_add((char *)req->gch.gwp_conf.app_key, req->gch.gwp_conf.dev_id);
			pthread_mutex_unlock(&gw_stat_mutex);

			pthread_mutex_lock(&mutex);
			res = PQexecParams(conn, db_query, 1, NULL, params, paramslen, paramsfor, 0);
			pthread_mutex_unlock(&mutex);

			if (PQresultStatus(res) == PGRES_COMMAND_OK) {
				PQclear(res);

				snprintf(db_query, sizeof(db_query),
					 "SELECT * FROM pend_msgs WHERE app_key='%s' and dev_id = %d and ack = False", 
					(char *)req->gch.gwp_conf.app_key, req->gch.gwp_conf.dev_id
				);
				
				pthread_mutex_lock(&mutex);
				res = PQexec(conn, db_query);
				pthread_mutex_unlock(&mutex);
				
				if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res)) {
					gateway_protocol_mk_stat(
						&(req->gch), 
						GATEWAY_PROTOCOL_STAT_ACK_PEND,
						req->packet, &(req->packet_length));
					printf("ACK_PEND prepared\n");
				} else {
					gateway_protocol_mk_stat(
						&(req->gch), 
						GATEWAY_PROTOCOL_STAT_ACK,
						req->packet, &(req->packet_length));
					printf("ACK prepared\n");
				}
				
				send_gcom_ch(&(req->gch), req->packet, req->packet_length);
			} else {
				fprintf(stderr, "database error : %s\n", PQerrorMessage(conn));
				gw_stat.errors_count++;
			}
			PQclear(res);
		} else if (req->packet_type == GATEWAY_PROTOCOL_PACKET_TYPE_PEND_REQ) {
			char db_query[200];
			snprintf(db_query, sizeof(db_query),
				 "SELECT * FROM pend_msgs WHERE app_key = '%s' AND dev_id = %d AND ack = False", 
				(char *)req->gch.gwp_conf.app_key, req->gch.gwp_conf.dev_id
			);
			pthread_mutex_lock(&mutex);
			res = PQexec(conn, db_query);
			pthread_mutex_unlock(&mutex);
			
			if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res)) {
				char msg_cont[150];
				strncpy(msg_cont, PQgetvalue(res, 0, 2), sizeof(msg_cont));
				printf("PEND_SEND prepared : %s\n", msg_cont);
				PQclear(res);
			
				base64_decode(msg_cont, strlen(msg_cont)-1, payload);
				payload_length = BASE64_DECODE_OUT_SIZE(strlen(msg_cont));
				printf("prepared to send %d bytes : %s\n", payload_length, payload);
				
				// send the msg until ack is received
				uint8_t received_ack = 0;
				uint8_t pend_send_retries = PEND_SEND_RETRIES_MAX;
				gateway_protocol_packet_encode(
					&(req->gch.gwp_conf),
					GATEWAY_PROTOCOL_PACKET_TYPE_PEND_SEND,
					payload_length, payload,
					&(req->packet_length), req->packet);
				do {
					send_gcom_ch(&(req->gch), req->packet, req->packet_length);
					
					// 300 ms
					usleep(300000);

					pthread_mutex_lock(&mutex);
					res = PQexec(conn, db_query);
					pthread_mutex_unlock(&mutex);
					
					if (PQresultStatus(res) == PGRES_TUPLES_OK) {
						if (!PQntuples(res) || strcmp(PQgetvalue(res, 0, 2), msg_cont)) {
							received_ack = 1;
						}
					}
					PQclear(res);
					printf("received_ack = %d, retries = %d\n", received_ack, pend_send_retries);
				} while (!received_ack && pend_send_retries--);
			} else {
				gateway_protocol_mk_stat(
					&(req->gch),
					GATEWAY_PROTOCOL_STAT_NACK,
					req->packet, &(req->packet_length));
				
				send_gcom_ch(&(req->gch), req->packet, req->packet_length);
				
				printf("nothing for app %s dev %d\n", (char *)req->gch.gwp_conf.app_key, req->gch.gwp_conf.dev_id);
			}
		} else if (req->packet_type == GATEWAY_PROTOCOL_PACKET_TYPE_STAT) {
			// TODO change to ACK_PEND = 0x01
			if (payload[0] == 0x00) {
				char db_query[200];
				snprintf(db_query, sizeof(db_query),
					 "SELECT * FROM pend_msgs WHERE app_key = '%s' AND dev_id = %d AND ack = False", 
					(char *)req->gch.gwp_conf.app_key, req->gch.gwp_conf.dev_id
				);
				pthread_mutex_lock(&mutex);
				res = PQexec(conn, db_query);
				pthread_mutex_unlock(&mutex);
				if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res)) {
					snprintf(db_query, sizeof(db_query),
						"UPDATE pend_msgs SET ack = True WHERE app_key = '%s' AND dev_id = %d AND msg = '%s'",
						(char *)req->gch.gwp_conf.app_key, req->gch.gwp_conf.dev_id, PQgetvalue(res, 0, 2)
					);
					PQclear(res);
					pthread_mutex_lock(&mutex);
					res = PQexec(conn, db_query);
					pthread_mutex_unlock(&mutex);
					if (PQresultStatus(res) == PGRES_COMMAND_OK) {
						printf("pend_msgs updated\n");
					} else {
						gw_stat.errors_count++;
						fprintf(stderr, "database error : %s\n", PQerrorMessage(conn));
					}
				}
				PQclear(res);
			}
		} else {
			gateway_protocol_mk_stat(
				&(req->gch),
				GATEWAY_PROTOCOL_STAT_NACK,
				req->packet, &(req->packet_length));
			
			send_gcom_ch(&(req->gch), req->packet, req->packet_length);
				
			fprintf(stderr, "packet type error : %02X\n", req->packet_type);
			gw_stat.errors_count++;
		}
	} else {
		fprintf(stderr, "payload decode error\n");
		gw_stat.errors_count++;
	}
		
	close(req->gch.client_desc);
	free(req);
}

uint8_t gateway_auth(const gw_conf_t *gw_conf, const char *dynamic_conf_file_path) {
	int sockfd;
	struct sockaddr_in platformaddr;
	uint8_t buffer[1024];
	uint16_t buffer_length = 0;
	uint8_t payload_buffer[1024];
	uint16_t payload_buffer_length = 0;
	FILE *fp;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return 0;
	}

	memset(&platformaddr, 0x0, sizeof(platformaddr));

	platformaddr.sin_family = AF_INET;
	platformaddr.sin_addr.s_addr = inet_addr(gw_conf->static_conf.platform_gw_manager_ip);
	platformaddr.sin_port = htons(gw_conf->static_conf.platform_gw_manager_port);
	
	if (connect(sockfd, (struct sockaddr *)&platformaddr, sizeof(platformaddr))) {
		return 0;
	}

	gateway_telemetry_protocol_encode_packet(buffer, 0, GATEWAY_TELEMETRY_PROTOCOL_AUTH, buffer, &buffer_length);
	write(sockfd, buffer, buffer_length);
	
	buffer_length = read(sockfd, buffer, sizeof(buffer));
	gateway_telemetry_protocol_packet_type_t pt;
	if (!gateway_telemetry_protocol_decode_packet(payload_buffer, &payload_buffer_length, &pt, buffer, buffer_length)) {
		return 0;
	}

	// write db_conf into file
	fp = fopen(dynamic_conf_file_path, "w");
	fwrite(payload_buffer, payload_buffer_length, 1, fp);
	fclose(fp);

	return 1;
}

#define GW_MNGR_BUF_LEN		1024
#define GW_MNGR_QBUF_LEN	1136
void * gateway_mngr(void *gw_cnf) {
	struct itimerval tval;
	gw_conf_t *gw_conf = (gw_conf_t *) gw_cnf;
	sigset_t alarm_msk;
	int sig;
	struct timeval tv;
	char buf[GW_MNGR_BUF_LEN];
	char qbuf[GW_MNGR_QBUF_LEN];
	char b64_gwid[12];
	PGresult *res;
	

	sigemptyset(&alarm_msk);
	sigaddset(&alarm_msk, SIGALRM);

	tval.it_value.tv_sec = gw_conf->dynamic_conf.telemetry_send_period;
	tval.it_value.tv_usec = 0;
	tval.it_interval.tv_sec = gw_conf->dynamic_conf.telemetry_send_period;
	tval.it_interval.tv_usec = 0;

	if (setitimer(ITIMER_REAL, &tval, NULL)) {
		perror("Failed to set itimer");
		return NULL;
	}

	base64_encode(gw_conf->static_conf.gw_id, GATEWAY_ID_SIZE, b64_gwid);
	
	while (1) {
		// get utc
		gettimeofday(&tv, NULL);

		// create applications and devices serving log
		pthread_mutex_lock(&gw_stat_mutex);
		gw_stat_linked_list_flush(buf, 0);
		pthread_mutex_unlock(&gw_stat_mutex);

		// flush utc and log into a query	
		snprintf(qbuf, GW_MNGR_QBUF_LEN, "UPDATE gateways SET num_errors = %lld, last_keep_alive = %d, last_report = '%s' WHERE id = '%s'",
				gw_stat.errors_count, (uint32_t) tv.tv_sec, buf, b64_gwid );

		pthread_mutex_lock(&mutex);
		res = PQexec(conn, qbuf);
		pthread_mutex_unlock(&mutex);
	
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			fprintf(stderr, "gateway manager db update failed!\n");
		}

		buf[0] = '\0';
		qbuf[0] = '\0';
		sigwait(&alarm_msk, &sig);
	}
}

void gateway_protocol_data_send_payload_decode(
	sensor_data_t *sensor_data, 
	const uint8_t *payload, 
	const uint8_t payload_length) 
{
	uint8_t p_len = 0;

	memcpy(&sensor_data->utc, &payload[p_len], sizeof(sensor_data->utc));
	p_len += sizeof(sensor_data->utc);

	memcpy(sensor_data->data, &payload[p_len], payload_length - p_len);
	sensor_data->data_length = payload_length - p_len;
}

void gateway_protocol_mk_stat(
	gcom_ch_t *gch,
	gateway_protocol_stat_t stat,
	uint8_t *pck,
	uint8_t *pck_len)
{
	gateway_protocol_packet_encode(
		&(gch->gwp_conf),
		GATEWAY_PROTOCOL_PACKET_TYPE_STAT,
		1, (uint8_t *)&stat,
		pck_len, pck);
}



void send_utc(gcom_ch_t *gch) {
	uint8_t buf[50];
	uint8_t buf_len = 0;
	struct timeval tv;
				
	gettimeofday(&tv, NULL);
				
	gateway_protocol_packet_encode (
		&(gch->gwp_conf),
		GATEWAY_PROTOCOL_PACKET_TYPE_TIME_SEND,
		sizeof(uint32_t), (uint8_t *)&tv.tv_sec,
		&buf_len, buf
	);
					
	send_gcom_ch(gch, buf, buf_len);
}

void gateway_protocol_checkup_callback(gateway_protocol_conf_t *gwp_conf) {
	PGresult *res;
	char db_query[200];
	
	snprintf(db_query, sizeof(db_query), 
		"SELECT secure_key, secure FROM applications WHERE app_key = '%s'", (char *)gwp_conf->app_key
	);
	pthread_mutex_lock(&mutex);
	res = PQexec(conn, db_query);
	pthread_mutex_unlock(&mutex);

	if ((PQresultStatus(res) == PGRES_TUPLES_OK) && PQntuples(res)) {
		base64_decode(PQgetvalue(res, 0, 0), strlen(PQgetvalue(res, 0, 0))-1, gwp_conf->secure_key);
		gwp_conf->secure = PQgetvalue(res, 0, 1)[0] == 't';
	} else {
		perror("gateway_protocol_checkup_callback error");
		gw_stat.errors_count++;
	}
	PQclear(res);
}

int send_gcom_ch(gcom_ch_t *gch, uint8_t *pck, uint8_t pck_size) {
	int ret;
	
	if ((ret = send(gch->client_desc, pck, pck_size, 0)) < 0) {
		gw_stat.errors_count++;
		perror("sendto error");
	}

	return ret;
}

int recv_gcom_ch(gcom_ch_t *gch, uint8_t *pck, uint8_t *pck_length, uint16_t pck_size) {
	int ret = -1;
	
	if ((gch->client_desc = accept(gch->server_desc, (struct sockaddr *)&gch->client, &gch->sock_len)) < 0) {
		perror("socket receive error");
		gw_stat.errors_count++;
	} else {
		*pck_length = recv(gch->client_desc, pck, pck_size, MSG_WAITALL);
	}

	return ret;
}


static void process_static_conf(json_value* value, static_conf_t *st_conf) {
	/* bad practice. must add checks for the EUI string */
	char buffer[128];
	strncpy(buffer, value->u.object.values[0].value->u.string.ptr, sizeof(buffer));
	sscanf(buffer, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &st_conf->gw_id[0], &st_conf->gw_id[1], &st_conf->gw_id[2],
							&st_conf->gw_id[3], &st_conf->gw_id[4], &st_conf->gw_id[5]
	);
	strncpy(buffer, value->u.object.values[1].value->u.string.ptr, sizeof(buffer));
	sscanf(buffer, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
			&st_conf->gw_secure_key[0], &st_conf->gw_secure_key[1], &st_conf->gw_secure_key[2], &st_conf->gw_secure_key[3],
			&st_conf->gw_secure_key[4], &st_conf->gw_secure_key[5], &st_conf->gw_secure_key[6], &st_conf->gw_secure_key[7],
			&st_conf->gw_secure_key[8], &st_conf->gw_secure_key[9], &st_conf->gw_secure_key[10], &st_conf->gw_secure_key[11],
			&st_conf->gw_secure_key[12], &st_conf->gw_secure_key[13], &st_conf->gw_secure_key[14], &st_conf->gw_secure_key[15]
	);
	st_conf->gw_port = value->u.object.values[2].value->u.integer;
	strncpy(st_conf->db_type, value->u.object.values[3].value->u.string.ptr, sizeof(st_conf->db_type));
	strncpy(st_conf->platform_gw_manager_ip, value->u.object.values[4].value->u.string.ptr, sizeof(st_conf->platform_gw_manager_ip));
	st_conf->platform_gw_manager_port = value->u.object.values[5].value->u.integer;
	st_conf->thread_pool_size = value->u.object.values[6].value->u.integer;
}

static void process_dynamic_conf(json_value* value, dynamic_conf_t *dyn_conf) {
	strncpy(dyn_conf->db_addr, value->u.object.values[0].value->u.string.ptr, sizeof(dyn_conf->db_addr));
	dyn_conf->db_port = atoi(value->u.object.values[1].value->u.string.ptr);
	strncpy(dyn_conf->db_name, value->u.object.values[2].value->u.string.ptr, sizeof(dyn_conf->db_name));
	strncpy(dyn_conf->db_user_name, value->u.object.values[3].value->u.string.ptr, sizeof(dyn_conf->db_user_name));
	strncpy(dyn_conf->db_user_pass, value->u.object.values[4].value->u.string.ptr, sizeof(dyn_conf->db_user_pass));
	dyn_conf->telemetry_send_period = value->u.object.values[5].value->u.integer;
}

static json_value * read_json_conf(const char *file_path) {
	struct stat filestatus;
	FILE *fp;
	char *file_contents;
	json_char *json;
	json_value *jvalue;

	if (stat(file_path, &filestatus)) {
		fprintf(stderr, "File %s not found.", file_path);
		return NULL;
	}
	file_contents = (char *)malloc(filestatus.st_size);
	if (!file_contents) {
		fprintf(stderr, "Memory error allocating %d bytes.", (int) filestatus.st_size);
		return NULL;
	}
	fp = fopen(file_path, "rt");
	if (!fp) {
		fprintf(stderr, "Unable to open %s.", file_path);
		fclose(fp);
		free(file_contents);
		return NULL;
	}
	if (fread(file_contents, filestatus.st_size, 1, fp) != 1) {
		fprintf(stderr, "Unable to read %s.", file_path);
		fclose(fp);
		free(file_contents);
		return NULL;
	}
	fclose(fp);
	
	file_contents[filestatus.st_size] = '\0';
	printf("file content : \n'%s'\n", file_contents);
	
	json = (json_char *)file_contents;
	jvalue = json_parse(json, filestatus.st_size);
	if (!jvalue) {
		perror("Unable to parse json.");
		free(file_contents);
		return NULL;
	}
	
	free(file_contents);
	
	return jvalue;
}

static int read_static_conf(const char *static_conf_file_path, gw_conf_t *gw_conf) {
	json_value *jvalue;
	
	jvalue = read_json_conf(static_conf_file_path);
	if (!jvalue) {
		return 1;
	}
	process_static_conf(jvalue, &gw_conf->static_conf);

	json_value_free(jvalue);
	
	return 0;
}

static int read_dynamic_conf(const char *dynamic_conf_file_path, gw_conf_t *gw_conf) {
	json_value *jvalue;
	
	jvalue = read_json_conf(dynamic_conf_file_path);
	if (!jvalue) {
		return 1;
	}
	process_dynamic_conf(jvalue, &gw_conf->dynamic_conf);

	json_value_free(jvalue);
	
	return 0;
}

