from os import urandom, system
import json
from hmac import new
from hashlib import sha1
from base64 import b64encode
from typing import Union
from time import time as timestamp
from requests import Session
from colored import fore
from time import sleep

class IpTemporaryBan(Exception):
	def __init__(*args, **kwargs):
		Exception.__init__(*args, **kwargs)

class VerifyError(Exception):
	def __init__(*args, **kwargs):
		Exception.__init__(*args, **kwargs)

class IncorrectEmail(Exception):
	def __init__(*args, **kwargs):
		Exception.__init__(*args, **kwargs)

class amino:
	def __init__(self):
		self.SIG_KEY = bytes.fromhex("DFA5ED192DDA6E88A12FE12130DC6206B1251E44")
		self.PREFIX = bytes.fromhex("19")
		self.DEVICE_KEY = bytes.fromhex("E7309ECC0953C6FA60005B2765F99DBBC965C8E9")
		self.api = "https://service.narvii.com/api/v1"
		self.session = Session()
		self.json_resp = None

	def generate_device_id(self):
		ur = self.PREFIX + (urandom(20))
		mac = new(self.DEVICE_KEY, ur, sha1)
		return f"{ur.hex()}{mac.hexdigest()}".upper()


	def signature(self, data: Union[str, bytes]):
		data = data if isinstance(data, bytes) else data.encode("utf-8")
		return b64encode(self.PREFIX + new(self.SIG_KEY, data, sha1).digest()).decode("utf-8")

	def header(self, deviceId, data = None):
		headers = {
			"NDCDEVICEID": deviceId,
			"NDCLANG": "ru",
			"Accept-Language": "ru-RU",
			"SMDEVICEID": "20230109055041eecd2b9dd8439235afe4522cb5dacd26011dba6bbfeeb752", 
			"User-Agent": 'Apple iPhone12,1 iOS v15.5 Main/3.12.2',
			"Content-Type": "application/json; charset=utf-8",
			"Host": "service.narvii.com",
			"Accept-Encoding": "gzip",
			"Connection": "Upgrade"
		}


		if data is not None:
			headers["Content-Length"] = str(len(data))
			headers["NDC-MSG-SIG"] = self.signature(data=data)

		return headers

	def login(self, email: str, password: str, deviceId: str):
		data = json.dumps({
			"email": email,
			"v": 2,
			"secret": f"0 {password}",
			"deviceID": deviceId,
			"clientType": 100,
			"action": "normal",
			"timestamp": int(timestamp() * 1000)
		})
		with self.session.post(f"{self.api}/g/s/auth/login",  headers=self.header(deviceId=deviceId, data=data), data=data) as response:
			if response.status_code != 200:raise self.Exceptions(response.text)
			else:json_response = json.loads(response.text)


	def Exceptions(self, data):
		try:
			data = json.loads(data)
			self.json_resp=data
			try:api_code = data["api:statuscode"]
			except:raise UnknownError(data)
		except json.decoder.JSONDecodeError:api_code = 403

		if api_code == 270:raise VerifyError(data)
		elif api_code == 403:raise IpTemporaryBan(data)
		elif api_code == 213:raise IncorrectEmail(data)
		else:raise Exception(data)


class Main:
	def __init__(self):
		self.acc_file = 'acc.txt'
		self.new_acc_file = 'updated_device.txt'
		self.format = 'account password deviceId'
		self.amino = amino()

		self.colors = {
			'magenta': fore.LIGHT_MAGENTA,
			'blue': fore.DEEP_SKY_BLUE_2,
			'grey': fore.GREY_93,
			'green': fore.GREEN,
			'red': fore.RED,
			'white':fore.WHITE
		}
		self.logo = f"""

		{self.colors['magenta']}

		╭━━╮╱╱╱╱╱╭╮╱╱╱╱╭┳╮╱╱╭╮╱╱╭╮
		╰╮╮┣━┳━┳━╋╋━┳━╮┃┃┣━┳╯┣━╮┃╰┳━┳┳╮
		╭┻╯┃┻╋╮┃╭┫┃━┫┻┫┃┃┃╋┃╋┃╋╰┫╭┫┻┫╭╯
		╰━━┻━╯╰━╯╰┻━┻━╯╰━┫╭┻━┻━━┻━┻━┻╯
		╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╱╰╯
			for amino.

			{self.colors['red']}
			Made By Xsarz -> @DXsarz
			{self.colors['blue']}
			GitHub: https://github.com/xXxCLOTIxXx
			Telegram channel: https://t.me/DxsarzUnion
			YouTube: https://www.youtube.com/channel/UCNKEgQmAvt6dD7jeMLpte9Q
			Discord server: https://discord.gg/GtpUnsHHT4
			{self.colors['white']}
		"""

	def load_acc(self):
		try:
			with open(self.acc_file, 'r') as file:
				self.accs = file.read().split('\n')
		except FileNotFoundError:
			print(f'{self.colors["red"]}\nФайл "{self.acc_file}" с аккаунтами не найден.{self.colors["white"]}\n')
			exit()


	def update(self):
		new_acc=[]
		for acc in self.accs:
			try:
				device = self.amino.generate_device_id()
				try:
					while True:
						try:self.amino.login(email=acc.split(' ')[0], password=acc.split(' ')[1], deviceId=device);break
						except VerifyError:
							print(f'{self.colors["red"]}\n[{acc.split(" ")[0]}]Перейдите по ссылке и пройдите капчу:{self.colors["magenta"]}\n{self.amino.json_resp["url"]}{self.colors["white"]}')
							input(f'{self.colors["white"]}\nНажмите любую клавишу после прохождения капчи.')
						except IpTemporaryBan:print(f'{self.colors["red"]}\nВременный бан, ожидаю 360 секунд для продолженя.{self.colors["white"]}\n');sleep(360)
				except IncorrectEmail: print(f'{self.colors["red"]}\nНекоректная почта.{self.colors["white"]}\n'); continue
				except:continue

				list_ = [acc.split(' ')[0], acc.split(' ')[1], device]
				new = ' '.join(list_)
				new_acc.append(new)
				print(f'{self.colors["green"]}\nАккаунт {acc.split(" ")[0]} обновлен{self.colors["white"]}\n')
			except IndexError: pass
		return new_acc

	def save(self):
		with open(self.new_acc_file, 'w') as file:
			file.write('\n'.join(self.update()))

	def main(self):
		system('cls || clear')
		print(self.logo)
		print(f'{self.colors["blue"]}\nПереместите в папку со скриптом файл с аккаунтами (должен называтся "{self.acc_file}")\n\nФормат записи данных акаунта должен быть таокй:\n{self.format}\n{self.format}\n{self.format}\n\n(Не обязательно иметь в конце девайс айди)')
		input(f'{self.colors["white"]}\nНажмите любую клавишу для продолжения.')
		self.load_acc()
		self.update()
		self.save()


if __name__ == '__main__':
	Main().main()