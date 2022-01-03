#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>

void parse_dns(const unsigned char *packet, t_analyzer *analyzer) {
	struct dns_hdr *hdr = (struct dns_hdr *)packet;
	//uint16_t flags = ntohs(hdr->flags);
	//uint16_t questions = ntohs(hdr->total_questions);
	//uint16_t answer_rr = ntohs(hdr->total_answer_rr);
	//uint16_t authority_rr = ntohs(hdr->total_authority_rr);
	//uint16_t additional_rr = ntohs(hdr->total_additional_rr);

    if (analyzer->info.verbosity == 1) {

    } else if (analyzer->info.verbosity == 2) {

    } else {
        printf("\t\t\t%sDNS%s\n", CSI_PURPLE, CSI_RESET);
        printf("\t\t\t%s%-10s%s0X%04X\n", CSI_PURPLE, "ID: ", CSI_RESET, ntohs(hdr->id));
        //
    }
	// log_formatln("%s%s", "Response: Message is a ",
	// 			 (flags & DNS_QR_MASK) == QR_QUERY ? "query" : "response");
	// log_formatln("%s: %s", "Opcode", DNS_OPCODE(flags));
	// log_formatln("%s: %s %s", "Authoritative",
	// 			 "Server is an authority for domain?",
	// 			 DNS_AA(flags) ? "yes" : "no");
	// log_formatln("%s: %s %s", "Truncated", "Message is truncated?",
	// 			 DNS_TC(flags) ? "yes" : "no");
	// log_formatln("%s: %s", "Recursion desired", DNS_RD(flags) ? "yes" : "no");
	// log_formatln("%s: %s", "Recursion available", DNS_RD(flags) ? "yes" : "no");
	// log_formatln("%s: %s %s", "Auth", "Answer was authenticated by server?",
	// 			 DNS_AD(flags) ? "yes" : "no");
	// log_formatln("%s: %s", "Non-authenticated data",
	// 			 DNS_CD(flags) ? "acceptable" : "unacceptable");
	// log_formatln("%s: %s", "Reply code", DNS_RCODE(flags));
	// set_offset(3);

	// log_formatln("%-15s%u", "Questions", questions);
	// log_formatln("%-15s%u", "Answer RRs", answer_rr);
	// log_formatln("%-15s%u", "Authority RRs", authority_rr);
	// log_formatln("%-15s%u", "Additional RRs", additional_rr);

	// uint8_t *payload = (uint8_t *)packet + sizeof(struct dns_hdr);

	// // Questions
	// if (questions > 0) {
	// 	set_offset(3);
	// 	log_formatln("Questions");
	// 	set_offset(4);

	// 	for (int i = 0; i < questions; i++) {
	// 		int name_len = 0, label_nb = 0;
	// 		log_formatln("Question %i", i + 1);
	// 		set_offset(5);
	// 		log_offset();
	// 		log_format("%-15s", "Name");
	// 		read_name((uint8_t *)hdr, &payload, &label_nb, &name_len);

	// 		log_formatln("%-15s%u", "[Name len]", name_len);
	// 		log_formatln("%-15s%u", "[Label nb]", label_nb);
	// 		log_formatln("%-15s%u", "Type", ntohs(*((uint16_t *)payload)));
	// 		payload += 2;
	// 		log_formatln("%-15s%u", "Class", ntohs(*((uint16_t *)payload)));
	// 		payload += 2;
	// 	}
	// }

	// // Answers
	// if (answer_rr > 0) {
	// 	set_offset(3);
	// 	log_formatln("Answers RR");
	// 	set_offset(4);

	// 	for (int i = 0; i < answer_rr; i++) {
	// 		set_offset(4);
	// 		log_formatln("- Answer %i", i + 1);
	// 		set_offset(5);
	// 		parse_rr((uint8_t *)hdr, &payload);
	// 	}
	// }

	// // Authority
	// if (authority_rr > 0) {
	// 	set_offset(3);
	// 	log_formatln("Authority RR");
	// 	set_offset(4);

	// 	for (int i = 0; i < answer_rr; i++) {
	// 		set_offset(4);
	// 		log_formatln("- Authority RR %i", i + 1);
	// 		set_offset(5);
	// 		parse_rr((uint8_t *)hdr, &payload);
	// 	}
	// }

	// // Additional
	// if (additional_rr > 0) {
	// 	set_offset(3);
	// 	log_formatln("Additional RR");
	// 	set_offset(4);

	// 	for (int i = 0; i < answer_rr; i++) {
	// 		set_offset(4);
	// 		log_formatln("- Additional RR %i", i + 1);
	// 		set_offset(5);
	// 		parse_rr((uint8_t *)hdr, &payload);
	// 	}
	// }

	// /**
	//  * SYNTH Verbosity
	//  */
	// set_verbosity(SYNTH);
	// set_offset(3);
	// log_offset();
	// log_format("Domain name system ");
	// if (questions) {
	// 	log_format("(question)");
	// } else if (answer_rr) {
	// 	log_format("(answer)");
	// }
	// log_format("\n");
}