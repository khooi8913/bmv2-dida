# DIDA
This repository holds the BMv2 implementation for DIDA, proposed in the [paper](https://ieeexplore.ieee.org/document/9165488), `DIDA: Distributed In-Network Defense Architecture Against Amplified Reflection DDoS Attacks` accepted at IEEE NetSoft 2020.

## Usage/ Notes
It is assumed that you are familiar with the P4 Tutorial environment.

Configuration steps/ notes: <br/>
1. Set `OP_MODE` register for each switch/ router (Edge = 0, Access/ TotR = 1)
2. Set `ROUTER_ID` register for each switch/ router
3. Current `THRESHOLD` is being set at 10 to ease the testing process.
4. TODO: CounterCheck process should be moved to the Ingress pipeline instead of being in the Egress pipeline, due to the fact that a packet's egress_spec cannot be modified after going through the PRE.
5. TODO: Modify forwarding rules for experiment purposes.

## Citation
If you find this work useful for your research, please cite:
```
@INPROCEEDINGS{9165488,
  author={Khooi, Xin Zhe and Csikor, Levente and Divakaran, Dinil Mon and Kang, Min Suk},
  booktitle={2020 6th IEEE Conference on Network Softwarization (NetSoft)}, 
  title={DIDA: Distributed In-Network Defense Architecture Against Amplified Reflection DDoS Attacks}, 
  year={2020},
  volume={},
  number={},
  pages={277-281},
  doi={10.1109/NetSoft48620.2020.9165488}}
```

## Feedback/ Questions
We welcome questions/ comments/ feedback.

Please do not hesitate reach out the authors via email.

## License
Copyright 2020 Xin Zhe Khooi, National University of Singapore.

The project's source code are released here under the [MIT License](https://opensource.org/licenses/MIT).
