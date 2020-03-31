# py -m pip install i2plib
# proxy1-1-1.i2p & proxy2-2-2.i2p
# run py script before executing malware
import asyncio
import i2plib


async def connect_test(destination):
    session_name = "test-connect"
    # create a SAM stream session
    await i2plib.create_session(session_name)
    # connect to a destination
    reader, writer = await i2plib.stream_connect(session_name, destination)
    # write data to a socket
    writer.write(b"PING")
    # asynchronously receive data
    data = await reader.read(4096)
    print(data.decode())
    # close the connection
    writer.close()


async def accept_test():
    session_name = "test-accept"
    # create a SAM stream session
    await i2plib.create_session(session_name)
    # accept a connection
    reader, writer = await i2plib.stream_accept(session_name)
    # first string on a client connection always contains clients I2P destination
    dest = await reader.readline()
    remote_destination = i2plib.Destination(dest.decode().strip())
    # read for the actual incoming data from the client
    data = await reader.read(4096)
    print(data.decode())
    # send data back
    writer.write(b"PONG")
    # close the connection
    writer.close()


def connect_to_i2p():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(connect_test("proxy2-2-2.i2p"))
    loop.stop()


def accept_i2p_connections():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(accept_test())
    loop.stop()


def bind_to_remote_i2p():
    loop = asyncio.get_event_loop()
    tunnel = i2plib.ClientTunnel("proxy2-2-2.i2p", ("127.0.0.1", 6669))
    asyncio.ensure_future(tunnel.run())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()


if __name__ == '__main__':
    #connect_to_i2p()
    accept_i2p_connections()
    #bind_to_remote_i2p()
