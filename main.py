import socket
import time
import gzip
import threading
import struct

NONE = ""

UBYTE = " B"
SBYTE = " b"
USHORT = " H"
SSHORT = " h"
UINT = " I"
SINT = " i"
STRING = " 64s"
ARRAY256 = " 256s"
ARRAY1024 = " 1024s"

SIZES = {
    UBYTE: 1,
    SBYTE: 1,
    USHORT: 2,
    SSHORT: 2,
    UINT: 4,
    SINT: 4,
    STRING: 64,
    ARRAY256: 256,
    ARRAY1024: 1024
}

class Packet:
    def __init__(self, packet_id, augment, handler):
        self.packet_id = packet_id
        self.augment = "!B " + augment
        self.handler = handler
        self.size = sum([SIZES[" " + i] for i in augment.split(" ") if i])

    def to_bytes(self, *args):
        return struct.pack(self.augment,
                           self.packet_id,
                           *[f"{i: <64}".encode("cp437") if isinstance(i, str) else i
                           for i in args])

    def from_bytes(self, data):
        if not isinstance(data, bytes):
            raise TypeError(f"a bytes-like object is required, not '{type(data)}'")
        if data[0] != self.packet_id:
            raise TypeError(f"first byte of data must be {self.packet_id}")
        
        return [i.decode("cp437").rstrip() if isinstance(i, bytes) and len(i) == 64 else i
                for i in struct.unpack(self.augment, data)]

class CPEClient:
    def __init__(self, botname, ip, port, mppass="", use_cpe=True):
        self.botname = botname
        self.ip      = ip
        self.port    = port
        self.mppass  = mppass
        self.use_cpe = use_cpe
        
        self.c_packets = {
            0x00: self.packet_0x00_c_player_identification,
            0x05: self.packet_0x05_c_set_block,
            0x08: self.packet_0x08_c_position_and_orientation,
            0x0d: self.packet_0x0d_c_message,

            "Player Identification": self.packet_0x00_c_player_identification,
            "Set Block": self.packet_0x05_c_set_block,
            "Position and Orientation": self.packet_0x08_c_position_and_orientation,
            "Message": self.packet_0x0d_c_message,
        }

        self.s_packets = {
            0x00: self.packet_0x00_s_server_identification,
            0x01: self.packet_0x01_s_ping,
            0x02: self.packet_0x02_s_level_initialize,
            0x03: self.packet_0x03_s_level_data_chunk,
            0x04: self.packet_0x04_s_level_finalize,
            0x06: self.packet_0x06_s_set_block,
            0x07: self.packet_0x07_s_spawn_player,
            0x08: self.packet_0x08_s_set_position_and_orientation,
            0x09: self.packet_0x09_s_position_and_orientation_update,
            0x0a: self.packet_0x0a_s_position_update,
            0x0b: self.packet_0x0b_s_orientation_update,
            0x0c: self.packet_0x0c_s_despawn_player,
            0x0d: self.packet_0x0d_s_message,
            0x0e: self.packet_0x0e_s_disconnect_player,
            0x0f: self.packet_0x0f_s_update_user_type,

            "Server Identification": self.packet_0x00_s_server_identification,
            "Ping": self.packet_0x01_s_ping,
            "Level Initialize": self.packet_0x02_s_level_initialize,
            "Level Data Chunk": self.packet_0x03_s_level_data_chunk,
            "Level Finalize": self.packet_0x04_s_level_finalize,
            "Set Block": self.packet_0x06_s_set_block,
            "Spawn Player": self.packet_0x07_s_spawn_player,
            "Set Position and Orientation": self.packet_0x08_s_set_position_and_orientation,
            "Position and Orientation Update": self.packet_0x09_s_position_and_orientation_update,
            "Position Update": self.packet_0x0a_s_position_update,
            "Orientation Update": self.packet_0x0b_s_orientation_update,
            "Despawn Player": self.packet_0x0c_s_despawn_player,
            "Message": self.packet_0x0d_s_message,
            "Disconnect player": self.packet_0x0e_s_disconnect_player,
            "Update user type": self.packet_0x0f_s_update_user_type,
        }
        
        self.running = False

        self.world      = []
        self.world_width = 0
        self.world_height = 0
        self.world_length = 0
        self.world_data = b""

        self.server_name = ""
        self.server_motd = ""
        
        self.x          = 0
        self.y          = 0
        self.z          = 0
        self.pitch      = 0
        self.yaw        = 0
        
        self.other_x     = [0 for _ in range(255)]
        self.other_y     = [0 for _ in range(255)]
        self.other_z     = [0 for _ in range(255)]
        self.other_pitch = [0 for _ in range(255)]
        self.other_yaw   = [0 for _ in range(255)]
        self.other_names = ["" for _ in range(255)]
        self.pslots_used = [False for _ in range(255)]

    def start(self):
        self.running = True

        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((self.ip, self.port))

        self.send_packet("Player Identification", 7, self.botname, self.mppass, 0)

        self.accept_thread = threading.Thread(target=self.accept)
        self.accept_thread.start()

    def accept(self):
        while self.running:
            packet_id = self.read_bytes(1)
            packet_id = int.from_bytes(packet_id, byteorder="big")

            data = packet_id.to_bytes(1, byteorder="big") + self.read_bytes(self.s_packets[packet_id].size)

            data = self.s_packets[packet_id].from_bytes(data)

            self.s_packets[packet_id].handler(self, data[1:])

    def send_bytes(self, data):
        self.connection.send(data)
        
    def read_bytes(self, n):
        data = self.connection.recv(n)

        while len(data) < n:
            data += self.connection.recv(n - len(data))

        return data

    def send_packet(self, packet_id, *args):
        self.send_bytes(self.c_packets[packet_id].to_bytes(*args))

        self.c_packets[packet_id].handler(self, args)
        
    def packet_0x00_s_server_identification_handler(self, args):
        version, server_name, server_motd, is_op = args

        if version != 7:
            print("Server dosen't support classic 0.28-0.30")
            
            self.running = False

        self.server_name = server_name
        self.server_motd = server_motd

    def packet_0x01_s_ping_handler(self, args):
        pass

    def packet_0x02_s_level_initialize_handler(self, args):
        self.world_data = b""

    def packet_0x03_s_level_data_chunk_handler(self, args):
        self.world_data += args[1][:args[0]]

    def packet_0x04_s_level_finalize_handler(self, args):
        self.world = list(gzip.decompress(self.world_data))

    def packet_0x06_s_set_block_handler(self, args):
        x, y, z, block_id = args

        self.world[x+(z*self.world_width)+(y*self.world_width*self.world_length)] = block_id

    def packet_0x07_s_spawn_player_handler(self, args):
        player_id, name, x, y, z, pitch, yaw  = args

        if player_id != 255:
            self.other_x[player_id]     = x
            self.other_y[player_id]     = y
            self.other_z[player_id]     = z
            self.other_pitch[player_id] = pitch
            self.other_yaw[player_id]   = yaw
            self.other_names[player_id] = name
            self.pslots_used[player_id] = True

    def packet_0x08_s_set_position_and_orientation_handler(self, args):
        player_id, x, y, z, pitch, yaw  = args

        if player_id == 255:
            self.x = x
            self.y = y
            self.z = z
            self.pitch = pitch
            self.yaw = yaw

            self.send_packet("Position and Orientation", 255, x, y, z, pitch, yaw)
        else:
            self.other_x[player_id]     = x
            self.other_y[player_id]     = y
            self.other_z[player_id]     = z
            self.other_pitch[player_id] = pitch
            self.other_yaw[player_id]   = yaw

    def packet_0x09_s_position_and_orientation_update_handler(self, args):
        pass

    def packet_0x0a_s_position_update_handler(self, args):
        pass

    def packet_0x0b_s_orientation_update_handler(self, args):
        pass

    def packet_0x0c_s_despawn_player_handler(self, args):
        self.pslots_used[args[0]] = False

    def packet_0x0d_s_message_handler(self, args):
        player_id, text = args

        if player_id > 127:
            text = "&e" + text

        print(text)

    def packet_0x0e_s_disconnect_player_handler(self, args):
        print(f"Bot got kicked:\n{args[0]}")

    def packet_0x0f_s_update_user_type_handler(self, args):
        pass

        
    def packet_0x00_c_player_identification_handler(self, args):
        pass

    def packet_0x05_c_set_block_handler(self, args):
        x, y, z, mode, block_id = args

        self.world[x+(z*self.world_width)+(y*self.world_width*self.world_length)] = (0 if mode == 0 else block_id)

    def packet_0x08_c_position_and_orientation_handler(self, args):
        pass

    def packet_0x0d_c_message_handler(self, args):
        print(args[1])
    
    packet_0x00_s_server_identification           = Packet(packet_id=0x00, handler=packet_0x00_s_server_identification_handler,           augment=UBYTE + STRING + STRING + UBYTE)
    packet_0x01_s_ping                            = Packet(packet_id=0x01, handler=packet_0x01_s_ping_handler,                            augment=NONE)
    packet_0x02_s_level_initialize                = Packet(packet_id=0x02, handler=packet_0x02_s_level_initialize_handler,                augment=NONE)
    packet_0x03_s_level_data_chunk                = Packet(packet_id=0x03, handler=packet_0x03_s_level_data_chunk_handler,                augment=SSHORT + ARRAY1024 + UBYTE)
    packet_0x04_s_level_finalize                  = Packet(packet_id=0x04, handler=packet_0x04_s_level_finalize_handler,                  augment=SSHORT + SSHORT + SSHORT)
    packet_0x06_s_set_block                       = Packet(packet_id=0x06, handler=packet_0x06_s_set_block_handler,                       augment=SSHORT + SSHORT + SSHORT + UBYTE)
    packet_0x07_s_spawn_player                    = Packet(packet_id=0x07, handler=packet_0x07_s_spawn_player_handler,                    augment=UBYTE + STRING + SSHORT + SSHORT + SSHORT + UBYTE + UBYTE)
    packet_0x08_s_set_position_and_orientation    = Packet(packet_id=0x08, handler=packet_0x08_s_set_position_and_orientation_handler,    augment=UBYTE + SSHORT + SSHORT + SSHORT + UBYTE + UBYTE)
    packet_0x09_s_position_and_orientation_update = Packet(packet_id=0x09, handler=packet_0x09_s_position_and_orientation_update_handler, augment=UBYTE + SBYTE + SBYTE + SBYTE + SBYTE + SBYTE)
    packet_0x0a_s_position_update                 = Packet(packet_id=0x0a, handler=packet_0x0a_s_position_update_handler,                 augment=UBYTE + SBYTE + SBYTE + SBYTE)
    packet_0x0b_s_orientation_update              = Packet(packet_id=0x0b, handler=packet_0x0b_s_orientation_update_handler,              augment=UBYTE + SBYTE + SBYTE)
    packet_0x0c_s_despawn_player                  = Packet(packet_id=0x0c, handler=packet_0x0c_s_despawn_player_handler,                  augment=UBYTE)  
    packet_0x0d_s_message                         = Packet(packet_id=0x0d, handler=packet_0x0d_s_message_handler,                         augment=UBYTE + STRING)
    packet_0x0e_s_disconnect_player               = Packet(packet_id=0x0e, handler=packet_0x0e_s_disconnect_player_handler,               augment=STRING)
    packet_0x0f_s_update_user_type                = Packet(packet_id=0x0f, handler=packet_0x0f_s_update_user_type_handler,                augment=UBYTE)

    packet_0x00_c_player_identification           = Packet(packet_id=0x00, handler=packet_0x00_c_player_identification_handler,           augment=UBYTE + STRING + STRING + UBYTE)
    packet_0x05_c_set_block                       = Packet(packet_id=0x05, handler=packet_0x05_c_set_block_handler,                       augment=SSHORT + SSHORT + SSHORT + UBYTE + UBYTE)
    packet_0x08_c_position_and_orientation        = Packet(packet_id=0x08, handler=packet_0x08_c_position_and_orientation_handler,        augment=UBYTE + SSHORT + SSHORT + SSHORT + UBYTE + UBYTE)
    packet_0x0d_c_message                         = Packet(packet_id=0x0d, handler=packet_0x0d_c_message_handler,                         augment=UBYTE + STRING)

bot = CPEClient("SB_bot", "144.217.42.65", 25612)

def packet_0x0d_s_message_handler(self, args):
    player_id, text = args

    if player_id > 127:
        text = "&e" + text

    print(text)

    if text.startswith("&cPlease complete account verification"):
        bot.send_packet("Message", 255, "/pass a")
    if text.startswith("&a+ "):
        bot.send_packet("Message", 255, "Welcome to the server, player! :D")
    if text.startswith("&c- "):
        bot.send_packet("Message", 255, "Goodbye! See you soon.")

bot.s_packets[0x0d].handler = packet_0x0d_s_message_handler

def spleef(bot):
    spleefrunning = False
    spleefplayers = []

    while True:
        time.sleep(0.05)
        if not spleefrunning:
            spleefplayers = [i for i in range(255) if bot.pslots_used[i]]
            spleefplayers = [i for i in spleefplayers
                             if  3648 > bot.other_x[i] > 3680
                             and 3744 > bot.other_z[i] > 3776]

            if len(spleefplayers):
                bot.send_packet("Message", 255, f"Starting spleef with {len(spleefplayers)} players")
                spleefrunning = True
        else:
            old_spleefplayers = len(spleefplayers)
            spleefplayers = [i for i in spleefplayers
                             if  3456 > bot.other_x[i] > 3968
                             and 3296 > bot.other_y[i] > 3424
                             and 3904 > bot.other_z[i] > 4416]

            for i in [i for i in old_spleefplayers if i not in spleefplayers]:
                bot.send_packet("Message", 255, f"{bot.other_names[i]} IS OUT!")

            if len(spleefplayers) == 1:
                bot.send_packet("Message", 255, f"{bot.other_names[spleefplayers[0]]} WINS!!!")
        
            
            
t = threading.Thread(target=spleef, args=(bot,))
t.start()

bot.start()
