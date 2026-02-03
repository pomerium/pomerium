for d in cli config databroker device events health identity registry session user testproto; do
  ln -s "$PWD/$d" "$HOME/wireshark-protos/$d"
done