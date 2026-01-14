create table cars (
	id BIGSERIAL NOT NULL PRIMARY KEY,
	make VARCHAR(100) NOT NULL ,
	model VARCHAR(100) NOT NULL,
	year VARCHAR(50) NOT NULL
);


create table employees (
	id BIGSERIAL NOT NULL PRIMARY KEY,
	first_name VARCHAR(50) NOT NULL,
	last_name VARCHAR(50) NOT NULL,
	email VARCHAR(50) NOT NULL,
	gender VARCHAR(50) NOT NULL,
	car_id BIGINT REFERENCES cars (id),
	UNIQUE(car_id)
);

insert into employees (id, first_name, last_name, email, gender) values (1, 'Cody', 'Bowery', 'cbowery0@arstechnica.com', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (2, 'Benn', 'Sabathier', 'bsabathier1@npr.org', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (3, 'Antonino', 'Hanwright', 'ahanwright2@blogspot.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (4, 'Kirbie', 'Gianettini', 'kgianettini3@comcast.net', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (5, 'Stesha', 'Loxton', 'sloxton4@slashdot.org', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (6, 'Celina', 'Swales', 'cswales5@csmonitor.com', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (7, 'Constance', 'Mepsted', 'cmepsted6@miitbeian.gov.cn', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (8, 'Nan', 'Thouless', 'nthouless7@about.com', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (9, 'Marietta', 'Kurten', 'mkurten8@163.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (10, 'Gasper', 'Wonham', 'gwonham9@cam.ac.uk', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (11, 'Shepherd', 'Sebrook', 'ssebrooka@dot.gov', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (12, 'Gilberto', 'McGinley', 'gmcginleyb@cam.ac.uk', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (13, 'Whitaker', 'Grumbridge', 'wgrumbridgec@mediafire.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (14, 'Curr', 'Trevarthen', 'ctrevarthend@moonfruit.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (15, 'Batholomew', 'Bertram', 'bbertrame@bigcartel.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (16, 'Amerigo', 'Vina', 'avinaf@creativecommons.org', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (17, 'Fanechka', 'Donet', 'fdonetg@nih.gov', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (18, 'Maurie', 'Scotchforth', 'mscotchforthh@reference.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (19, 'Merell', 'Yoxall', 'myoxalli@mashable.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (20, 'Fredrick', 'Pitone', 'fpitonej@baidu.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (21, 'Maxie', 'Grellis', 'mgrellisk@godaddy.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (22, 'Cullie', 'Ferneyhough', 'cferneyhoughl@devhub.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (23, 'Bert', 'Atteridge', 'batteridgem@posterous.com', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (24, 'Fitz', 'Pentycost', 'fpentycostn@storify.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (25, 'Maddy', 'Gregorin', 'mgregorino@trellian.com', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (26, 'Mendel', 'Shingler', 'mshinglerp@amazon.de', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (27, 'Spenser', 'Koppen', 'skoppenq@people.com.cn', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (28, 'Olivia', 'Castelluzzi', 'ocastelluzzir@ow.ly', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (29, 'Eryn', 'Kayley', 'ekayleys@hugedomains.com', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (30, 'Celle', 'McTerlagh', 'cmcterlaght@msn.com', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (31, 'Frankie', 'Mewha', 'fmewhau@arstechnica.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (32, 'Tammie', 'Dunguy', 'tdunguyv@simplemachines.org', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (33, 'Stanly', 'Sillett', 'ssillettw@theglobeandmail.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (34, 'Elliot', 'Lenden', 'elendenx@reference.com', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (35, 'Avigdor', 'Tilmouth', 'atilmouthy@51.la', 'Male');
insert into employees (id, first_name, last_name, email, gender) values (36, 'Theressa', 'Hellikes', 'thellikesz@ustream.tv', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (37, 'Kalie', 'Austwick', 'kaustwick10@purevolume.com', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (38, 'Jocelyn', 'Samme', 'jsamme11@dagondesign.com', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (39, 'Viv', 'Piser', 'vpiser12@omniture.com', 'Female');
insert into employees (id, first_name, last_name, email, gender) values (40, 'Glenn', 'Plowright', 'gplowright13@bing.com', 'Female');

insert into cars (id, make, model, year) values (1, 'Volkswagen', 'Jetta', 1997);
insert into cars (id, make, model, year) values (2, 'Hyundai', 'Tiburon', 2000);
insert into cars (id, make, model, year) values (3, 'Acura', 'Integra', 1999);
insert into cars (id, make, model, year) values (4, 'Mitsubishi', 'GTO', 1998);
insert into cars (id, make, model, year) values (5, 'Mitsubishi', 'Montero', 1994);
insert into cars (id, make, model, year) values (6, 'Mitsubishi', 'Lancer', 2004);
insert into cars (id, make, model, year) values (7, 'GMC', 'Yukon XL 2500', 2012);
insert into cars (id, make, model, year) values (8, 'Dodge', 'Shadow', 1993);
insert into cars (id, make, model, year) values (9, 'Jaguar', 'S-Type', 2002);
insert into cars (id, make, model, year) values (10, 'Lincoln', 'Navigator L', 2011);
insert into cars (id, make, model, year) values (11, 'Toyota', 'MR2', 2003);
insert into cars (id, make, model, year) values (12, 'Dodge', 'Caravan', 2010);
insert into cars (id, make, model, year) values (13, 'Dodge', 'Stratus', 2006);
insert into cars (id, make, model, year) values (14, 'Dodge', 'Dakota Club', 2001);
insert into cars (id, make, model, year) values (15, 'Cadillac', 'SRX', 2011);
insert into cars (id, make, model, year) values (16, 'Volvo', 'C70', 2013);
insert into cars (id, make, model, year) values (17, 'Bentley', 'Continental Super', 2010);
insert into cars (id, make, model, year) values (18, 'Volkswagen', 'Cabriolet', 1986);
insert into cars (id, make, model, year) values (19, 'Volvo', 'S80', 1999);
insert into cars (id, make, model, year) values (20, 'Acura', 'RDX', 2010);
insert into cars (id, make, model, year) values (21, 'Plymouth', 'Breeze', 1999);
insert into cars (id, make, model, year) values (22, 'Saab', '900', 1988);
insert into cars (id, make, model, year) values (23, 'Ford', 'F350', 2000);
insert into cars (id, make, model, year) values (24, 'Volkswagen', 'GTI', 2006);
insert into cars (id, make, model, year) values (25, 'Nissan', 'Altima', 2013);
insert into cars (id, make, model, year) values (26, 'Volvo', 'XC90', 2005);
insert into cars (id, make, model, year) values (27, 'Cadillac', 'Escalade ESV', 2003);
insert into cars (id, make, model, year) values (28, 'Mazda', 'MPV', 2006);
insert into cars (id, make, model, year) values (29, 'Mazda', 'MX-5', 1997);
insert into cars (id, make, model, year) values (30, 'Volkswagen', 'Corrado', 1991);
insert into cars (id, make, model, year) values (31, 'Mercedes-Benz', 'E-Class', 1989);
insert into cars (id, make, model, year) values (32, 'Maserati', 'Coupe', 2006);
insert into cars (id, make, model, year) values (33, 'Toyota', 'Venza', 2010);
insert into cars (id, make, model, year) values (34, 'Land Rover', 'Discovery', 2000);
insert into cars (id, make, model, year) values (35, 'Cadillac', 'Brougham', 1992);
insert into cars (id, make, model, year) values (36, 'Pontiac', 'Turbo Firefly', 1988);
insert into cars (id, make, model, year) values (37, 'Buick', 'Regal', 1999);
insert into cars (id, make, model, year) values (38, 'Chevrolet', 'G-Series G20', 1993);
insert into cars (id, make, model, year) values (39, 'Jeep', 'Cherokee', 1992);
insert into cars (id, make, model, year) values (40, 'Mercedes-Benz', 'R-Class', 2012);