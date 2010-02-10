struct uidl {
	char *txt;
	int fd;
};

struct uidl *uidl_read(char *filename);
int uidl_find(struct uidl *uidl, char *id);
void uidl_add(struct uidl *uidl, char *id);
void uidl_save(struct uidl *uidl);
