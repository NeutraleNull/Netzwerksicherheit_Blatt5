all : clean restore build publish createKeys

clean:
	dotnet clean


restore:
	dotnet restore

build: 
	dotnet build

publish:
	dotnet publish -c Release -r linux-x64
	warp-packer --arch linux-x64 --input_dir bin/Release/netcoreapp2.1/linux-x64/publish --exec made --output made

createKeys:
	openssl req -x509 -newkey rsa:4096 -keyout server_key.pem -out server_cert.pem -sha256 -days 365 -nodes -subj '/CN=localhost'
	openssl req -x509 -newkey rsa:4096 -keyout client_key.pem -out client_cert.pem -sha256 -days 365 -nodes

copyKeys:
	

run:
	dotnet run