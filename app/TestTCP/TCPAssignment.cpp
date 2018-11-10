//3-1

#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

#include <list>
#include <assert.h>

#include <arpa/inet.h>

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{
}

void TCPAssignment::initialize()
{
	//just for printing warning when running my code.
	int a;
	// std::cout<<"initialize\n";
}

void TCPAssignment::finalize()
{
	// std::cout<<"finalize\n";
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, void * buffer, int n){
	fake_read(syscallUUID, pid, sockfd, buffer,n);
}


void TCPAssignment::fake_read(UUID syscallUUID, int pid, int sockfd, void * buffer, int n){
	int unread_data_in_packet;
	Packet * e;
	int N_copy;

	uint8_t * char_buffer = (uint8_t *)buffer;

	struct socket * socket = find_fd(pid, sockfd);

	/* Block read if read buffer empty */
	if(socket->read_buffer_size == 0){
		socket->read_block = true;
		socket->read_uuid = syscallUUID;
		socket->r_buffer = char_buffer;
		socket->r_n = n;
		return;
	}

	/* reset blocking stuff */
	socket->read_block = false;
	socket->read_uuid = 0;
	socket->r_buffer = NULL;
	socket->r_n = 0;

	/* How many bytes to read? Guaranteed to read N. */
	int N = minimum2(socket->read_buffer_size, n);

	/* Copy those bytes to application's buffer */
	N_copy = N;
	while(N != 0){//until N bytes have been written
		e = socket->read_buffer->front();
		unread_data_in_packet = (e->getSize()-54) - socket->packet_data_read;

		/* Read remaining data in packet, and free packet */
		if(N >= unread_data_in_packet){
			e->readData(54+socket->packet_data_read, (void *)char_buffer, unread_data_in_packet);
			char_buffer += unread_data_in_packet;
			N -= unread_data_in_packet;
			socket->read_buffer_size -= unread_data_in_packet;

			socket->read_buffer->pop_front();
			freePacket(e);

			socket->packet_data_read = 0;
		}

		/* Read a bit of the packet. Read N. */
		else{
			e->readData(54+socket->packet_data_read, (void *)char_buffer, N);
			char_buffer += N;
			socket->read_buffer_size -= N;
			socket->packet_data_read += N;
			N -= N;
		}
	}

	/* Return */
	this->returnSystemCall(syscallUUID, N_copy);
	return; 



	// memcpy(buffer, socket->read_buffer, N);

	// /* Adjust read buffer */
	// char temp[socket->read_buffer_size - N];
	// memcpy(temp, socket->read_buffer + N, socket->read_buffer_size - N);
	// memcpy(buffer, temp, socket->read_buffer_size - N);

	// /* Adjust size */
	// socket->read_buffer_size -= N;

	// /* Return */
	// this->returnSystemCall(syscallUUID, N_copy);
	// return;

	//initialise read buffer when packetArrived.
	//What about ack retransmission? keep track of last ack only.
	//what about buffering out of order packets. 
}


void TCPAssignment::fake_write(UUID syscallUUID, int pid, int sockfd, void * buffer, int n){
	int N;
	struct socket * socket;
	Packet * packet;

	uint8_t * char_buffer = (uint8_t *)buffer;


	/* Get socket to get connection information */
	socket = find_fd(pid,sockfd);
	assert(socket->state == TCP_state::ESTAB);

	/* Block write if full */
	if(socket->write_buffer_size == 51200){
		socket->write_block = true;
		socket->write_uuid = syscallUUID;
		socket->w_buffer = char_buffer;
		socket->w_n = n;
		return;
	}


	/* Initialise variables used for blocking everytime */
	socket->write_block = false;
	socket->write_uuid = 0;
	socket->w_buffer = NULL;
	socket->w_n = 0;

	//control flow- when rwnd is 0
	N = minimum4(51200-socket->write_buffer_size, n, 512, socket->last_rwnd);
	if(N == 0){
		this->returnSystemCall(syscallUUID, 0);
		return;
	}

	packet = makeDataPacket((void *)char_buffer, N,
		socket->source_ip, socket->dest_ip,
		socket->source_port, socket->dest_port,
		socket->sequence_number, socket->last_ack, 0b00010000);

	socket->write_buffer->push_back(packet);
	socket->write_buffer_size += N;

	socket->sequence_number += N;

	if(!socket->timer_running){
		start_timer(socket);
	}
	this->sendPacket("IPv4", this->clonePacket(packet));
	this->returnSystemCall(syscallUUID, N);


	return;
}


// /* Calculate how much data to write to sender buffer */
// N = 51200-write_buffer_size < n? 51200-write_buffer_size: n;

// /* Break into MSS */
// int number_of_packets = N/512 + ((N%512 == 0)? 0: 1);
// for(int i = 0; i < number_of_packets; i++){
// 	uint32_t data_size = ( (i == number_of_packets-1)? (N-(number_of_packets-1)*512): (512));

// 	/* Make a data packet */
// 	packet = makeDataPacket(buffer + 512*i, data_size, 
// 		socket->source_ip, socket->dest_ip,
// 		socket->source_port, socket->dest_port,
// 		socket->sequence_number, socket->last_ack, 0b00010000);//always ack for some reason. Therefore, just keep sending the same ack number from connection establishment since server doesn't send any data.

// 	/* Add to write buffer */
// 	write_buffer.push_back(packet);
// 	write_buffer_size += data_size;

// 	/* Update socket information */
// 	socket->sequence_number += data_size;

// 	/* Send packet */
// 	this->sendPacket("IPv4", this->clonePacket(packet));
// }

// /* Return */
// this->returnSystemCall(syscallUUID, N);
// return;



void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, void * buffer, int n){
	fake_write(syscallUUID, pid, sockfd, buffer,n);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr* sa, socklen_t * len){
	/*
	I assume there could be multiple listening sockets.
	Therefore each listening socket requires an estab_list to know which socket to accept.
	*/


	/* Find listening socket */
	struct socket * listening_socket = find_fd(pid,sockfd);
	assert(listening_socket != NULL && listening_socket->listen == true);

	/* There are completed connections */
	if(listening_socket->estab_list!= NULL && !(listening_socket->estab_list->empty())){
		
		/* Get the established socket and remove from list */
		struct socket * socket =  listening_socket->estab_list->front();
		listening_socket->estab_list->pop_front();


		/* Fill in sockaddr */
		struct sockaddr_in * si = (struct sockaddr_in *) sa;
		struct in_addr * ia = (struct in_addr *) (&(si->sin_addr));
		ia->s_addr = socket->dest_ip;
		si->sin_family = AF_INET;
		si->sin_port = htons(socket->dest_port);

		this->returnSystemCall(syscallUUID, socket->fd);
		return;
	}

	/* If no established connection, block */
	listening_socket->accept_block = true;
	listening_socket->uuid = syscallUUID;
	listening_socket->sockaddr = sa;

}


//Two scenarios:
//1) Connection established before accept.
//2) Accept before connection
		//-> blocked accept -> fakeaccept called -> uuid reset -> accept returns.
//only called when accept was called already.
void TCPAssignment::fake_accept(struct socket * listening_socket){


	UUID syscallUUID = listening_socket->uuid;

	/* This is only called when there are ready pending connections */
	assert(listening_socket->estab_list!= NULL && !(listening_socket->estab_list->empty()));

	/* Get ready pending connection and remove from list */
	struct socket * socket = listening_socket->estab_list->front();
	listening_socket->estab_list->pop_front();

	/* Fill in sockaddr */
	struct sockaddr_in * si = (struct sockaddr_in *) listening_socket->sockaddr;
	struct in_addr * ia = (struct in_addr *) (&(si->sin_addr));
	ia->s_addr = socket->dest_ip;
	si->sin_family = AF_INET;
	si->sin_port = htons(socket->dest_port);

	/* Accept consumed one established connection, so reset uuid for another acccept */
	listening_socket->accept_block = false;
	listening_socket->uuid = 0;
	listening_socket->sockaddr = NULL;
	this->returnSystemCall(syscallUUID, socket->fd);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog){
	
	//return 0 on success, -1 on error.
	struct socket * socket = find_fd(pid, sockfd);
	if(socket == NULL){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}


	assert(socket->bound);

	//mark it listen - important for searching later.
	socket->listen = true;
	socket->backlog = backlog;

	socket->state = TCP_state::LISTEN; // state = listen

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd,struct sockaddr * addr, socklen_t * addrlen){
	/* Return 0 on success, -1 on error */

	// initialise to this always?
	*addrlen = sizeof(struct sockaddr);

	//find peer adddress by looking at socket.
	struct socket * socket = find_fd(pid, sockfd);
	if(socket == NULL){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	struct sockaddr_in * si = (struct sockaddr_in *) addr;
	struct in_addr * ia= (struct in_addr *) (&(si->sin_addr));

	//set ip.
	ia->s_addr = socket->dest_ip;

	//set sin_family in sockaddr_in
	si->sin_family = AF_INET;

	//set sin_port in sockaddr_in
	si->sin_port = htons(socket->dest_port);

	this->returnSystemCall(syscallUUID, 0);
	//DIDN'T DO THE LENGHT CUT OFF STUFF. RETS DIFFERENT VALUES?
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int){
	int fd = this->createFileDescriptor(pid);
	create_socket(pid, fd);
	this->returnSystemCall(syscallUUID, fd);//systemcallinterface function.
}


void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int param1_int, struct sockaddr*sa, socklen_t socklen){
	uint16_t source_port = 0;	//dest and source addrs.
	uint32_t source_ip = 0;
	uint16_t dest_port = 0;
	uint32_t dest_ip = 0;

	int index = 0;	//other declarations.
	bool success;
	Host * host;

	/* Implicit bind- fill in socket. */
	struct socket * socket = find_fd(pid, param1_int);
	if(socket == NULL){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	else if(socket->bound){	//use address in socket if bound already.
		source_ip = socket->source_ip;
		source_port = socket->source_port;
	}
	else{
		// Get source ip and port
		host = this->getHost();
		index = host->getRoutingTable( (uint8_t*) &(dest_ip) );
		success = host->getIPAddr( (uint8_t*)(&source_ip), index);
		if(!success){
			this->returnSystemCall(syscallUUID, -1);
			return;
		}
		source_port = get_port();

		/* Check overlap then bind. */
		if(check_overlap_source(pid, param1_int, source_ip, source_port)){	//this is probs uncessary here.
			this->returnSystemCall(syscallUUID, -1);
			return;
		}else{
			bind(pid, param1_int, source_ip, source_port);
		}
	}
	socket->state = TCP_state::LISTEN;

	/* Extract destination address */
	struct sockaddr_in * si = (struct sockaddr_in *) sa;
	dest_ip = (&(si->sin_addr))->s_addr;
	dest_port = ntohs(si->sin_port);
	socket->dest_ip = dest_ip; //do not assign destinatino port, because this is listenig port.
	socket->dest_port = dest_port;

	/* make syn packet */
	Packet * packet = makeHeaderPacket(source_ip, dest_ip,source_port,dest_port,socket->sequence_number,0,0b00000010,51200);

	socket->write_buffer->push_back(packet);
	//don't increment size.

	/* update socket states */
	socket->sequence_number++;
	socket->state = TCP_state::SYNSENT;
	socket->uuid = syscallUUID;	//since connect is blocking.

	/* Send SYN packet-> */
	start_timer(socket);
	this->sendPacket("IPv4", this->clonePacket(packet));
	return;
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int param1_int){
	// std::cout<<"close\n";
	int fd = param1_int;

	/* Find socket */
	struct socket * socket = find_fd(pid,fd);
	if(socket == NULL){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}


	if(socket->listen){
		//if we remove listening socket from socket list, other sockets may not finish closing(4-way handshake) and fail.
		this->removeFileDescriptor(pid, fd);
		this->returnSystemCall(syscallUUID, 0);
		return;
	}
	else if(socket->state == TCP_state::SYNSENT){
		socket->state = TCP_state::CLOSED;
		this->removeFileDescriptor(pid, fd);
		this->returnSystemCall(syscallUUID, 0);
		return;
	}
	else if(socket->state == TCP_state::ESTAB){
		//Send FIN packet
		Packet * packet = this->allocatePacket(54);
		packet->writeData(14+12, &(socket->source_ip), 4);
		packet->writeData(14+16, &(socket->dest_ip), 4);

		/* Make packet header */
		struct TCP_header * header = make_header(socket->source_ip,socket->dest_ip, 
			socket->source_port,socket->dest_port,
			socket->sequence_number,0,0b00000001,51200);

		/* Write header to packet */
		packet->writeData(34,header,20);

		/* Add to write buffer */
		socket->write_buffer->push_back(packet);
		//don't increment size-done writing anyways.adding to buffer just for retransmission.

		/* Update socket states */
		socket->sequence_number++;
		socket->state = TCP_state::FIN_WAIT1;

		/* Free struct */
		delete(header);

		/* Send FIN packet */
		if(socket->timer_running == false){
			start_timer(socket);
		}
		this->removeFileDescriptor(pid, fd);
		this->sendPacket("IPv4", this->clonePacket(packet));
		this->returnSystemCall(syscallUUID,0);
		return;
	}
	else if(socket->state == TCP_state::CLOSE_WAIT){
		//Send FIN packet
		Packet * packet = this->allocatePacket(54);
		packet->writeData(14+12, &(socket->source_ip), 4);
		packet->writeData(14+16, &(socket->dest_ip), 4);

		/* Make packet header */
		struct TCP_header * header = make_header(socket->source_ip,socket->dest_ip, 
			socket->source_port,socket->dest_port,
			socket->sequence_number,0,0b00000001,51200);

		/* Write header to packet */
		packet->writeData(34,header,20);

		/* Update socket states */
		socket->sequence_number++;
		socket->state = TCP_state::LAST_ACK;

		/* Free struct */
		delete(header);

		/* Send FIN packet */
		this->removeFileDescriptor(pid, fd);
		this->sendPacket("IPv4", packet);
		this->returnSystemCall(syscallUUID,0);
		return;
	}
	else if(socket->state == TCP_state::SYNRCVD){
		//Send FIN packet
		Packet * packet = this->allocatePacket(54);
		packet->writeData(14+12, &(socket->source_ip), 4);
		packet->writeData(14+16, &(socket->dest_ip), 4);

		/* Make packet header */
		struct TCP_header * header = make_header(socket->source_ip,socket->dest_ip, 
			socket->source_port,socket->dest_port,
			socket->sequence_number,0,0b00000001,51200);

		/* Write header to packet */
		packet->writeData(34,header,20);

		/* Update socket states */
		socket->sequence_number++;
		socket->state = TCP_state::FIN_WAIT1;

		/* Free struct */
		delete(header);

		/* Send FIN packet */
		this->removeFileDescriptor(pid, fd);
		this->sendPacket("IPv4", packet);
		this->returnSystemCall(syscallUUID,0);
		return;
	}
	else{//state = NONE
		this->removeFileDescriptor(pid, fd);
		this->returnSystemCall(syscallUUID,0);
		remove_fd(pid, fd);
		return;
	}
}


//bind is only for server.
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr * sa,
				socklen_t param3_int){
	struct sockaddr_in * si = (struct sockaddr_in *) sa;
	uint16_t source_port = ntohs(si->sin_port);
	struct in_addr ia= (struct in_addr) (si->sin_addr);
	long source_ip = ia.s_addr;


	if(check_overlap_source(pid, sockfd, source_ip, source_port)){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}else{
		bind(pid, sockfd, source_ip, source_port);
		assert(find_fd(pid, sockfd)!=NULL);
		this->returnSystemCall(syscallUUID, 0);
		return;
	}
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, 
	struct sockaddr * sa, socklen_t * socklen){

	struct socket * e = find_fd(pid, fd);
	if(e == NULL){
		this->returnSystemCall(syscallUUID,-1);
		return;
	}

	struct sockaddr_in * si = (struct sockaddr_in *) sa;
	struct in_addr * ia= (struct in_addr *) (&(si->sin_addr));

	//set ip.
	ia->s_addr = e->source_ip;

	//set sin_family in sockaddr_in
	si->sin_family = AF_INET;

	//set sin_port in sockaddr_in
	si->sin_port = htons(e->source_port);

	this->returnSystemCall(syscallUUID,0);
}



void TCPAssignment::timerCallback(void* payload)
{
	// std::cout<<"Timer callback\n";
	struct socket * socket = (struct socket *) payload;


	//for now assert, since we are only donig retransmission timers.
	assert(!socket->write_buffer->empty());
	assert(socket->timer_running);

	//retransmit and restart timer
	Packet * e = socket->write_buffer->front();
	socket->timer_uuid = this->addTimer(socket, RTT);
	this->sendPacket("IPv4", this->clonePacket(e));



	//stop listening for FIN, and assume ACK was well received on the other end.
	//so free socket.
	// struct socket * socket = (struct socket *) payload;
	// assert(socket->pending_list->size() == 0 && socket->estab_list->size() == 0);	
	// remove_fd(socket->pid, socket->fd);
}


void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

	
	Packet * new_packet;

	struct TCP_header * rcv_header = new struct TCP_header;

	uint32_t sender_src_ip = 0;
	uint16_t sender_src_port = 0;
	uint32_t sender_dest_ip = 0;
	uint16_t sender_dest_port = 0;

	/* Read ip, port, and TCP Header */	
	packet->readData(14 + 12, &sender_src_ip, 4);		//ip
	packet->readData(14 + 16, &sender_dest_ip, 4);
	packet->readData(34 + 0, (void *)rcv_header, 20);	//header
	sender_src_port = ntohs(rcv_header->source_port);	//port
	sender_dest_port = ntohs(rcv_header->dest_port);

	/* Verify checksum */
	int temp_size = packet->getSize()-34;
	char temp_array[temp_size];
	packet->readData(34, temp_array,temp_size);
	if( tcp_sum(sender_src_ip, sender_dest_ip, (uint8_t *)temp_array, temp_size) != 0xffff){
		free_resources(packet, rcv_header);
		return;
	}


	/* Do listening socket first */
	struct socket * listening_socket = find_listening_socket_source(sender_dest_ip, sender_dest_port);
	if(listening_socket!= NULL){
		if(rcv_header->flags == 0b00000010){//listening socket only checks for syn. afterwards, new server socket handles connection.
			/* Create new socket and add to list */
			struct socket * socket;
			if(listening_socket->pending_list == NULL){
				listening_socket->pending_list = new std::list<struct socket *>;
			}

			if((uint16_t)listening_socket->backlog != listening_socket->pending_list->size()){
				
				/* Create new socket for incoming connection request */
				int fd = this->createFileDescriptor(listening_socket->pid);
				if(check_overlap_dest(listening_socket->pid,fd, sender_src_ip,sender_src_port)){
					removeFileDescriptor(listening_socket->pid, fd);
					free_resources(packet, rcv_header);
					return;
				}
				socket = create_socket(listening_socket->pid, fd);
				bind(listening_socket->pid, fd, sender_dest_ip, sender_dest_port);
				socket->dest_port = sender_src_port;
				socket->dest_ip = sender_src_ip;

				/* Add to pending list */
				listening_socket->pending_list->push_back(socket);

			}else{
				free_resources(packet, rcv_header);
				return;
			}

			/* Make packet */
			new_packet = makeHeaderPacket(sender_dest_ip,sender_src_ip,
				ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),
				socket->sequence_number,ntohl(rcv_header->sequence_number)+1,0b00010010,51200);

			/* Update socket state */
			socket->state = TCP_state::SYNRCVD;
			socket->sequence_number++;
			socket->last_ack = ntohl(rcv_header->sequence_number)+1;

			/* Free resources */
			free_resources(packet, rcv_header);

			/* Send SYNACK packet */
			this->sendPacket("IPv4", new_packet);
			return;
		}
		//don't do anything so we can move on to code below.
	}

	/* Handle TCP states */
	struct socket * socket = find_socket(sender_dest_ip, sender_dest_port,sender_src_ip,sender_src_port);

	if(socket->state == TCP_state::SYNSENT){

		/* Receive SYNACK or SYN */
		if(rcv_header->flags == 0b00010010){//SYNACK
			/* Send ACK packet */

			/* Verify ACK number */
			if( ntohl(rcv_header->ack_number) != socket->sequence_number){
				returnSystemCall(socket->uuid, -1);
				free_resources(packet, rcv_header);
				return;
			}

			/* Free SYN packet in write buffer */
			Packet * e = socket->write_buffer->front();
			socket->write_buffer->pop_front();
			uint8_t flags;
			e->readData(FLAGS_OFFSET,&flags,1);
			assert(flags == SYN_FLAG);//verify it's syn packet in write buffer
			freePacket(e);

			//cancel timer
			assert(socket->timer_running);
			cancel_timer(socket);

			/* Make packet */
			new_packet = makeHeaderPacket(sender_dest_ip,sender_src_ip,ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number,ntohl(rcv_header->sequence_number)+1,0b00010000,51200);

			/* Update states */
			socket->state = TCP_state::ESTAB;
			socket->last_ack = ntohl(rcv_header->sequence_number)+1;//dafuq?
			socket->receiver_sequence_number = ntohl(rcv_header->sequence_number)+1;
			
			free_resources(packet, rcv_header);

			/* Send ACK Packet */
			this->sendPacket("IPv4", new_packet);
			this->returnSystemCall(socket->uuid, 0);
			return;
		}
		else if(rcv_header->flags == 0b00000010){//SYN - simultaneous connect case
			/* Send SYNACK packet */

			/* Reset seqeunce number since basically starting new connection as a server socket */
			socket->sequence_number--;

			/* Make packet header and write to packet */
			new_packet = makeHeaderPacket(sender_dest_ip,sender_src_ip,ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number,ntohl(rcv_header->sequence_number)+1,0b00010010,51200);

			/* Update socket state */
			socket->state = TCP_state::SYNRCVD;
			socket->sequence_number++;

			/* Free resources */
			free_resources(packet, rcv_header);

			/* Send SYNACK Packet */
			this->sendPacket("IPv4", new_packet);
			return;
		}
		else{
			free_resources(packet, rcv_header);
			return;
		}

	}
	else if(socket->state == TCP_state::SYNRCVD){

		if(rcv_header->flags == 0b00010010){//synack--not in state diagram, but it's simmultaneous connect.
			/* Send ACK, become established */
			/* Verify */
			if( ntohl(rcv_header->ack_number) != socket->sequence_number){
				free_resources(packet, rcv_header);
				return;
			}

			/* Make packet */
			new_packet = makeHeaderPacket(sender_dest_ip,sender_src_ip,ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number,ntohl(rcv_header->sequence_number)+1,0b00010000,51200);

			/* Update states */
			socket->state = TCP_state::ESTAB;
			// socket->last_ack = ntohl(rcv_header->sequence_number)+1;

			free_resources(packet, rcv_header);

			/* Send ACK Packet */
			this->sendPacket("IPv4", new_packet);
			this->returnSystemCall(socket->uuid, 0);
			return;

		}
		else if(rcv_header->flags == 0b00010000){//ack
			/* Become established */
			
			/* Verify */
			if( ntohl(rcv_header->ack_number) != socket->sequence_number){		//if wrong ack number.
				free_resources(packet, rcv_header);
				return;
			}

			/* Free */
			free_resources(packet, rcv_header);

			/* Connection established */
			socket->state = TCP_state::ESTAB;

			/* If we got to this state as a server socket, not a client socket(simultaneous connect) */
			if(listening_socket != NULL){
				/* Remove from pending list */
				find_and_remove_from_list( listening_socket->pending_list, socket);

				/* Add to estab list */
				if(listening_socket->estab_list == NULL){
					listening_socket->estab_list = new std::list<struct socket *>;
				}
				listening_socket->estab_list->push_back(socket);

				/* Call fake accept if blocked */
				if(listening_socket->accept_block){
					fake_accept(listening_socket);
				}
				return;
			}
		}
		else{
			free_resources(packet, rcv_header);
			return;
		}

	}
	else if(socket->state == TCP_state::ESTAB){
		/* Should receive FIN(or data), send ACK packet */

		if(rcv_header->flags == 0b00000001){//fin
			/* Make packet */
			new_packet = makeHeaderPacket(sender_dest_ip, sender_src_ip,ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number, ntohl(rcv_header->sequence_number)+1,0b00010000,51200);

			/* Update states */
			socket->state = TCP_state::CLOSE_WAIT;

			if(socket->read_block){
				this->returnSystemCall(socket->read_uuid, -1);
			}
			if(socket->write_block){//this one's not necessary.
				this->returnSystemCall(socket->write_uuid, -1);
			}

			/* Free */
			free_resources(packet, rcv_header);

			/* Send ACK packet */
			this->sendPacket("IPv4", new_packet);
			return;

		}
		else if(rcv_header->flags == 0b00010000){//ack-data arrived

			//if there is any data in the packet, write to read buffer. 

			/* Two types of packets arriving
				1) ACK packets NO data
					- Update write buffer

				2) ACK packets WITH data
					- Send ACK
					- Write to read buffer
					- update write buffer
			*/

			if(packet->getSize() == 54){//Pure ACK packet

				int ack_number;
				int seq_number;
				int data_length;
				Packet * e;

				//update window first when receiving ack
				socket->last_rwnd = ntohs(rcv_header->window_size);

				//if receiver retransmit ACK instead of SYNACK in 3 way(sometimes happens)
				if(socket->write_buffer->empty()){
					free_resources(packet, rcv_header);
					return;
				}

				//ack and free packets in write buffer
				ack_number = ntohl(rcv_header->ack_number);
				e = socket->write_buffer->front();
				e->readData(38, &seq_number, 4);
				seq_number = ntohl(seq_number);
				data_length = e->getSize()-54;

				//if there are packets to be acked in write buffer
				if( seq_number < ack_number){

					while(seq_number != ack_number){
						//remove from list and free
						assert(!socket->write_buffer->empty());
						socket->write_buffer->pop_front();
						freePacket(e);
						socket->write_buffer_size -= data_length;

						//if acked all in buffer
						if(socket->write_buffer->empty()){
							assert(seq_number+data_length == ack_number);//must be directly after
							break;
						}

						//get next
						e = socket->write_buffer->front();
						e->readData(38, &seq_number, 4);
						seq_number = ntohl(seq_number);
						data_length = e->getSize()-54;
					}

					//no more unacked data
					if(socket->write_buffer->empty()){
						cancel_timer(socket);
					}
					//more unacked data, refresh timer
					else{
						restart_timer(socket);
					}

					//unblock write
					if(socket->write_block){
						fake_write(socket->write_uuid, socket->pid, socket->fd, socket->w_buffer, socket->w_n);
					}
				}

				//duplicate ack
				else{
					if(seq_number == ack_number){
						socket->duplicate_ack++;
						if(socket->duplicate_ack == 3){
							socket->duplicate_ack = 0;
							Packet * e = socket->write_buffer->front();
							this->sendPacket("IPv4", this->clonePacket(e));
						}
					}
					//other acks ignored(ack no.<seq no.)- late arriving acks of retransmitted packets.
				}
				
				free_resources(packet, rcv_header);
				return;
			}

			else{//ACK with data
				//data has arrived.
				//consider blocked read. 
				//do not do out of order packets for now.

				/* No space */
				if(socket->read_buffer_size + (packet->getSize()-54) > 51200){
					free_resources(packet, rcv_header);
					return;
				}

				/* Add to read buffer */
				socket->read_buffer->push_back( this->clonePacket(packet));
				socket->read_buffer_size += packet->getSize()-54;

				/* Unblock read */
				if(socket->read_block){
					fake_read(socket->read_uuid, socket->pid, socket->fd, socket->r_buffer,socket->r_n );
				}

				/* Send ACK */
				Packet * new_packet = makeHeaderPacket(sender_dest_ip, sender_src_ip, ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number, ntohl(rcv_header->sequence_number)+packet->getSize()-54,0b00010000,51200-socket->read_buffer_size);
				this->sendPacket("IPv4", new_packet);

				free_resources(packet, rcv_header);
				return;
			}

		}

		else if(rcv_header->flags == SYNACK_FLAG){//synack- retransmission scenario(not in state diagram)
			//retransmit ack(of 3 way handshake)
			Packet * new_packet = makeHeaderPacket(sender_dest_ip, sender_src_ip,ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number, ntohl(rcv_header->sequence_number)+1, 0b00010000, 51200-socket->read_buffer_size);
			this->sendPacket("IPv4", new_packet);

			free_resources(packet, rcv_header);
			return;
		}


		else{
			free_resources(packet, rcv_header);
			return;
		}
	}
	else if(socket->state == TCP_state::FIN_WAIT1){

		if(rcv_header->flags == 0b00010000){//ack

			std::cout<<"ack: "<< ntohl(rcv_header->ack_number) - debug<<"\n";

			int ack_number;
			int seq_number;
			int data_length;
			Packet * e;

			//update window first when receiving ack.
			socket->last_rwnd = ntohs(rcv_header->window_size);

			//cannot be empty, since at least fin packet must be in there.(different from estab)
			assert(!socket->write_buffer->empty());

			ack_number = ntohl(rcv_header->ack_number);
			e = socket->write_buffer->front();
			e->readData(38, &seq_number, 4);
			seq_number = ntohl(seq_number);
			data_length = e->getSize()-54;

			//if there are packets to be acked in write buffer
			if( seq_number < ack_number){
				while(seq_number!= ack_number){
					//remove from list and free
					assert(!socket->write_buffer->empty());
					socket->write_buffer->pop_front();
					freePacket(e);
					socket->write_buffer_size -= data_length;

					//if acked all in buffer
					if(socket->write_buffer->empty()){
						assert(seq_number+data_length == ack_number || seq_number+data_length+1 == ack_number);//must be directly after or +1 in case of fin
						break;
					}

					//get next
					e = socket->write_buffer->front();
					e->readData(38, &seq_number ,4 );
					seq_number = ntohl(seq_number);
					data_length = e->getSize()-54;
				}

				//no more unacked data
				if(socket->write_buffer->empty()){
					cancel_timer(socket);

					/* Update states */
					socket->state = TCP_state::FIN_WAIT2;
				}
				//unacked data remaining
				else{
					restart_timer(socket);
				}

				//unblock write-don't need this here since cannot send data after close.
				if(socket->write_block){
					assert(0);
					fake_write(socket->write_uuid, socket->pid, socket->fd, socket->w_buffer, socket->w_n);
				}
			}

			else{
				//duplicate ack
				if(seq_number == ack_number){
					socket->duplicate_ack++;
					if(socket->duplicate_ack == 3){
						// std::cout<<"dup ack\n";
						//retransmit
						socket->duplicate_ack = 0;
						Packet * e = socket->write_buffer->front();
						this->sendPacket("IPv4", this->clonePacket(e));
					}
				}
				//other acks ignored(ack no.<seq no.)- late arriving ack from previous state(estab)
			}

			/* Free */
			free_resources(packet, rcv_header);
			return;
		}
		else if(rcv_header->flags == 0b00000001){//fin

			/* Make packet */
			new_packet = makeHeaderPacket(sender_dest_ip, sender_src_ip,ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number, ntohl(rcv_header->sequence_number)+1,0b00010000,51200);

			/* Update states */
			socket->state = TCP_state::CLOSING;

			/* Free */
			free_resources(packet, rcv_header);

			/* Send ACK packet */
			this->sendPacket("IPv4", new_packet);
			return;
		}
		else if(rcv_header->flags == 0b00010001){//finack
			if( ntohl(rcv_header->ack_number) != socket->sequence_number){	//if wrong ack number.
				std::cout<<"finack doesn't ack everything\n";
				free_resources(packet, rcv_header);
				return;
			}

			//ack everything
			int ack_number;
			int seq_number;
			int data_length;
			Packet * e;

			socket->last_rwnd = ntohs(rcv_header->window_size);

			//cannot be empty, since at least fin packet must be in there.(different from estab)
			assert(!socket->write_buffer->empty());

			ack_number = ntohl(rcv_header->ack_number);
			e = socket->write_buffer->front();
			e->readData(38, &seq_number, 4);
			seq_number = ntohl(seq_number);
			data_length = e->getSize()-54;

			//if there are packets to be acked in write buffer
			while(seq_number != ack_number){
				//remove from list and free
				assert(!socket->write_buffer->empty());
				socket->write_buffer->pop_front();
				freePacket(e);
				socket->write_buffer_size -= data_length;

				//if acked all in buffer
				if(socket->write_buffer->empty()){
					assert(seq_number+data_length == ack_number || seq_number+data_length+1 == ack_number);//must be directly after
					break;
				}

				//get next
				e = socket->write_buffer->front();
				e->readData(38, &seq_number ,4 );
				seq_number = ntohl(seq_number);
				data_length = e->getSize()-54;
			}

			assert(socket->write_buffer->empty());
			cancel_timer(socket);

			/* Make ack packet */
			new_packet = makeHeaderPacket(sender_dest_ip, sender_src_ip,ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number, ntohl(rcv_header->sequence_number)+1,0b00010000,51200);

			/* Update states */
			socket->state = TCP_state::TIME_WAIT;

			/* Start timer(2*MSL = 4mins = 240 secs) */
			// this->addTimer((void *)socket, 240000000000);

			/* Free */
			free_resources(packet, rcv_header);

			/* Send ACK packet */
			this->sendPacket("IPv4", new_packet);
			return;
		}else{//random
			free_resources(packet, rcv_header);
			return;
		}
	}
	else if(socket->state == TCP_state::FIN_WAIT2){

		/* Verify */
		if( tcp_sum(sender_src_ip, sender_dest_ip, (uint8_t *)rcv_header, 20) != 0xffff){
			free_resources(packet, rcv_header);
			return;
		}
		if( rcv_header->flags != 0b00000001){
			free_resources(packet, rcv_header);
			return;
		}

		/* Make packet */
		new_packet = makeHeaderPacket(sender_dest_ip, sender_src_ip,ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number, ntohl(rcv_header->sequence_number)+1,0b00010000,51200);

		/* Update states */
		socket->state = TCP_state::TIME_WAIT;

		/* Start timer(2*MSL = 4mins = 240 secs) */
		// this->addTimer((void *)socket, 240000000000);

		/* Free */
		free_resources(packet, rcv_header);

		/* Send ACK packet */
		this->sendPacket("IPv4", new_packet);
		return;
	}
	else if(socket->state == TCP_state::CLOSING){

		if(rcv_header->flags == FIN_FLAG){//fin-retransmission from peer
			if(ntohl(rcv_header->sequence_number != socket->receiver_sequence_number)){
				free_resources(packet, rcv_header);
				return;
			}

			/* Make packet */
			new_packet = makeHeaderPacket(sender_dest_ip,sender_src_ip,ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number,ntohl(rcv_header->sequence_number)+1,ACK_FLAG,51200);

			/* Free*/
			free_resources(packet, rcv_header);

			/* Send ACK packet */
			this->sendPacket("IPv4", new_packet);
			return;

		}
		else if(rcv_header->flags == ACK_FLAG){//acking data + fin packet in write buffer
			int ack_number;
			int seq_number;
			int data_length;
			Packet * e;

			//update window first when receiving ack.
			socket->last_rwnd = ntohs(rcv_header->window_size);

			//cannot be empty, since at least fin packet must be in there.(different from estab)
			assert(!socket->write_buffer->empty());

			ack_number = ntohl(rcv_header->ack_number);
			e = socket->write_buffer->front();
			e->readData(38, &seq_number, 4);
			seq_number = ntohl(seq_number);
			data_length = e->getSize()-54;

			//if there are packets to be acked in write buffer
			if( seq_number < ack_number){
				while(seq_number!= ack_number){
					//remove from list and free
					assert(!socket->write_buffer->empty());
					socket->write_buffer->pop_front();
					freePacket(e);
					socket->write_buffer_size -= data_length;

					//if acked all in buffer
					if(socket->write_buffer->empty()){
						assert(seq_number+data_length == ack_number || seq_number+data_length+1 == ack_number);//must be directly after
						break;
					}

					//get next
					e = socket->write_buffer->front();
					e->readData(38, &seq_number ,4 );
					seq_number = ntohl(seq_number);
					data_length = e->getSize()-54;
				}

				//no more unacked data
				if(socket->write_buffer->empty()){
					cancel_timer(socket);
					/* Update states */
					socket->state = TCP_state::TIME_WAIT;
				}
				//unacked data remaining
				else{
					restart_timer(socket);
				}
			}
			else{
				//duplicate ack
				if(seq_number == ack_number){
					socket->duplicate_ack++;
					if(socket->duplicate_ack == 3){
						//retransmit
						socket->duplicate_ack = 0;
						Packet * e = socket->write_buffer->front();
						this->sendPacket("IPv4", this->clonePacket(e));
					}
				}
				//other acks ignored(ack no.<seq no.)- late arriving ack from previous state
			}

			/* Free */
			free_resources(packet, rcv_header);
			return;
		}

		else{
			std::cout<<"yo wtf is here?\n";
			free_resources(packet, rcv_header);
			return;
		}



		/* Update states */
		// socket->state = TCP_state::TIME_WAIT;

		/* Start timer(2*MSL = 4mins = 240 secs) */
		// this->addTimer((void *)socket, 240000000000);

		/* Free */
		// free_resources(packet, rcv_header);

		// return;
	}
	else if(socket->state == TCP_state::LAST_ACK){

		if( ntohl(rcv_header->ack_number) != socket->sequence_number){	//if wrong ack number.
			free_resources(packet, rcv_header);
			return;
		}
		/* Update states */
		socket->state = TCP_state::CLOSED;

		/* Free */
		free_resources(packet, rcv_header);

		return;
	}

	else if(socket->state == TCP_state::TIME_WAIT){
		//could receive late fin packets. need to keep acking them so server could finish too.
		if(rcv_header->flags == FIN_FLAG){
			if(ntohl(rcv_header->sequence_number != socket->receiver_sequence_number)){//if wrong sequence number
				free_resources(packet, rcv_header);
				return;
			}

			/* Make packet */
			new_packet = makeHeaderPacket(sender_dest_ip,sender_src_ip,ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number,ntohl(rcv_header->sequence_number)+1,ACK_FLAG,51200);

			/* Free*/
			free_resources(packet, rcv_header);

			/* Send ACK packet */
			this->sendPacket("IPv4", new_packet);
			return;
		}

		else if(rcv_header->flags == FINACK_FLAG){//finack retranmission.
			//send ack
			new_packet = makeHeaderPacket(sender_dest_ip,sender_src_ip,ntohs(rcv_header->dest_port),ntohs(rcv_header->source_port),socket->sequence_number, ntohl(rcv_header->sequence_number)+1, ACK_FLAG, 51200);
			free_resources(packet, rcv_header);
			this->sendPacket("IPv4", new_packet);
			return;
		}
		else{
			//ignore delayed acks
			free_resources(packet, rcv_header);
			return;
		}
	}
	else{
		/* Free packet-since we dont need */
		free_resources(packet, rcv_header);
	}
}

//no need to provide list here since should search server list obviously.
struct socket * TCPAssignment::find_listening_socket_source(uint32_t source_ip, uint16_t source_port){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if( e->listen == true && ((e->source_ip == source_ip) || e->source_ip ==0) && e->source_port == source_port){
			return e;
		}
	}
	return NULL;
}

struct socket * TCPAssignment::find_socket(uint32_t source_ip, uint16_t source_port,uint32_t dest_ip, uint16_t dest_port){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if( e->listen == false && ((e->source_ip == source_ip) || e->source_ip ==0) && ((e->dest_ip == dest_ip) || e->dest_ip ==0) && e->source_port == source_port && e->dest_port == dest_port){
			return e;
		}
	}
	return NULL;
}

//finds normal socket(not listening).
struct socket * TCPAssignment::find_socket_source(uint32_t source_ip, uint16_t source_port){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if( e->listen == false && ((e->source_ip == source_ip) || e->source_ip ==0) && e->source_port == source_port){
			return e;
		}
	}
	return NULL;
}


struct socket * TCPAssignment::find_socket_dest(uint32_t dest_ip, uint16_t dest_port){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if(((e->dest_ip == dest_ip) || e->dest_ip ==0) && e->dest_port == dest_port){
			return e;
		}
	}
	return NULL;
} 


//checks overlap with any type of socket.
bool TCPAssignment::check_overlap_source(int pid, int fd, uint32_t ip, uint16_t port){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!= socket_list.end();++it){
		e = *it;

		//fd already bound if fd are same for same process.(e->bound is extra)
		if(e->fd == fd && e->pid == pid && e->bound){
			return true;
		}

		//overlap.
		if( ((ip == e->source_ip)||(ip ==0)||(e->source_ip ==0)) && port == e->source_port){
			return true;
		}
	}
	return false;
}

//checks dest address overlap.
bool TCPAssignment::check_overlap_dest(int pid, int fd, uint32_t ip, uint16_t port){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;

		//fd already bound.
		if(e->fd == fd && e->pid == pid && e->bound){
			return true;
		}

		//overlap.
		if( ((ip == e->dest_ip)||(ip ==0)||(e->dest_ip ==0)) && port == e->dest_port){
			return true;
		}
	}
	return false;
}

void TCPAssignment::bind(int pid, int fd, uint32_t source_ip, uint16_t source_port){

	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if(e->fd == fd && pid == e->pid){
			e->bound = true;
			e->source_port = source_port;
			e->source_ip = source_ip;
			break;
		}
	}
}

struct socket * TCPAssignment::find_fd(int pid, int fd){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if(e->fd == fd && e->pid == pid){
			return e;
		}
	}
	return NULL;
}

void TCPAssignment::remove_fd(int pid, int fd){
	struct socket * e;
	for(std::list<struct socket *>::iterator it = socket_list.begin(); it!=socket_list.end();++it){
		e = *it;
		if(e->fd == fd && e->pid == pid){
			delete(e->write_buffer);
			delete(e->read_buffer);
			delete(e->pending_list);
			delete(e->estab_list);
			delete(e);
			socket_list.erase(it);
			break;
		}
	}
}

void TCPAssignment::find_and_remove_from_list(std::list<struct socket *> * list, struct socket * socket){
	struct socket * e;

	for(std::list<struct socket *>::iterator it = list->begin(); it!= list->end(); ++it){
		e = *it;
		if(e == socket){
			list->erase(it);
			return;
		}
	}
}

struct socket * TCPAssignment::create_socket(int pid, int fd){
	struct socket * e = new struct socket;

	e->timer_uuid = 0;
	e->timer_running = false;
	e->duplicate_ack = 0;

	e->estab_list = NULL;
	e->pending_list = NULL;
	e->accept_block = false;
	e->sockaddr = NULL;
	e->uuid = 0;

	e->fd = fd;
	e->pid = pid;
	e->sequence_number = rand();
	debug = e->sequence_number;
	e->last_ack = 0;
	e->last_rwnd = 51200;

	e->receiver_sequence_number = 0;

	//write buffer
	e->write_buffer = new std::list<Packet *>;
	e->write_buffer_size = 0;

	//things for write block
	e->write_block = false;
	e->write_uuid = 0;
	e->w_buffer = NULL;
	e->w_n = 0;

	//read buffer
	e->read_buffer = new std::list<Packet *>;
	e->read_buffer_size = 0;
	e->packet_data_read = 0;

	//things for read block
	e->read_block = false;
	e->read_uuid = 0;
	e->r_buffer = NULL;
	e->r_n = 0;



	e->state = TCP_state::NONE;
	e->bound = false;
	e->listen = false;
	e->backlog = 0;
	e->source_ip = 0;
	e->source_port = 0;
	e->dest_ip = 0;
	e->dest_port = 0;

	socket_list.push_back(e);

	return e;
}

uint16_t TCPAssignment::get_port(){
	return max_port++;
}


uint16_t TCPAssignment::tcp_sum(uint32_t source, uint32_t dest, uint8_t* buffer, size_t length)
{
	if(length < 20)
		return 0;
	struct pseudoheader pheader;
	pheader.source = source;
	pheader.destination = dest;
	pheader.zero = 0;
	pheader.protocol = IPPROTO_TCP;
	pheader.length = htons(length);

	uint32_t sum = one_sum((uint8_t*)&pheader, sizeof(pheader));
	sum += one_sum(buffer, length);
	sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)sum;
}

uint16_t TCPAssignment::one_sum(uint8_t * buffer, size_t size)
{
	bool upper = true;
	uint32_t sum = 0;
	for(size_t k=0; k<size; k++)
	{
		if(upper)
		{
			sum += buffer[k] << 8;
		}
		else
		{
			sum += buffer[k];
		}

		upper = !upper;

		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)sum;
}

//used for packets with data
Packet * TCPAssignment::makeDataPacket(
	void * buffer, uint32_t data_size,
	uint32_t source_ip, uint32_t dest_ip,
	uint16_t source_port, uint16_t dest_port,
	uint32_t seq_number, uint32_t ack_number,uint8_t flags){

	//buffer for tcp header and data
	char * checksum_buffer = new char[20+data_size];
	struct TCP_header * header = make_header(source_ip, dest_ip, source_port,dest_port,seq_number,ack_number, flags,51200);
	header->checksum = 0;
	memcpy(checksum_buffer, header, 20);
	memcpy(checksum_buffer+20, buffer, data_size);
	header->checksum = htons(~(this->tcp_sum(source_ip,dest_ip, (uint8_t *)checksum_buffer, 20+data_size)));
	delete[] checksum_buffer;

	//create packet
	Packet * packet = this->allocatePacket(54 + data_size);
	packet->writeData(14 + 12, &source_ip, 4);
	packet->writeData(14 + 16, &dest_ip, 4);
	packet->writeData(34, header, 20);
	packet->writeData(54, buffer, data_size);
	delete(header);

	return packet;
}

//used for syn,ack,fin,synack. packets with no data.
Packet * TCPAssignment::makeHeaderPacket(
	uint32_t source_ip, uint32_t dest_ip,
	uint16_t source_port, uint16_t dest_port,
	uint32_t seq_number, uint32_t ack_number,uint8_t flags, uint16_t window_size){

	Packet * packet = this->allocatePacket(54);
	packet->writeData(14 + 12, &source_ip, 4);
	packet->writeData(14 + 16, &dest_ip, 4);

	struct TCP_header * header = make_header(source_ip, dest_ip, source_port, dest_port,seq_number, ack_number,flags,window_size);
	packet->writeData(34, header, 20);
	delete(header);

	return packet;
}

struct TCP_header * TCPAssignment::make_header(
	uint32_t source_ip, uint32_t dest_ip, 
	uint16_t source_port, uint16_t dest_port, 
	uint32_t seq_number, uint32_t ack_number,uint8_t flags,uint16_t window_size){

	struct TCP_header * header = new struct TCP_header;
	header->source_port = htons(source_port);
	header->dest_port = htons(dest_port);
	header->sequence_number = htonl(seq_number);
	header->ack_number = htonl(ack_number);
	header->first_byte = ((5)<<4);	//header size = 20bytes(5 words)
	header->flags = flags;
	header->window_size = htons(window_size);
	header->urgent_ptr = 0;
	header->checksum = 0;
	header->checksum = htons(~(this->tcp_sum((source_ip),(dest_ip),(uint8_t *)header,20)));
	return header;
}


void TCPAssignment::free_resources(Packet * packet, struct TCP_header * header){
	freePacket(packet);
	delete(header);
}

int TCPAssignment::minimum2(int a, int b){
	if(a <= b){
		return a;
	}else{
		return b;
	}
}

int TCPAssignment::minimum4(int a, int b, int c, int d){

	if(a <= b && a <= c && a<= d){
		return a;
	}
	else if(b <= a && b <=c && b <= d){
		return b;
	}
	else if(c <= a && c <= b && c<= d){
		return c;
	}else{
		return d;
	}
}


void TCPAssignment::start_timer(struct socket * socket){
	socket->timer_uuid = this->addTimer(socket, RTT);
	socket->timer_running = true;
}

void TCPAssignment::restart_timer(struct socket * socket){
	cancel_timer(socket);
	start_timer(socket);
}

void TCPAssignment::cancel_timer(struct socket * socket){
	this->cancelTimer(socket->timer_uuid);
	socket->timer_uuid = 0;
	socket->timer_running = false;
}

}
